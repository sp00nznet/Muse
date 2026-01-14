"""Datadog API client service for fetching host information."""
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
import requests
from cryptography.fernet import Fernet

from app import db
from app.models import DatadogIntegration, DatadogHostCache


def get_encryption_key():
    """Get encryption key for decrypting API keys."""
    key = os.environ.get('MUSE_ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
        os.environ['MUSE_ENCRYPTION_KEY'] = key
    return key.encode() if isinstance(key, str) else key


def encrypt_value(value: str) -> str:
    """Encrypt a sensitive value."""
    if not value:
        return None
    f = Fernet(get_encryption_key())
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a sensitive value."""
    if not encrypted_value:
        return None
    try:
        f = Fernet(get_encryption_key())
        return f.decrypt(encrypted_value.encode()).decode()
    except Exception:
        return encrypted_value


class DatadogClient:
    """Client for interacting with Datadog API."""

    def __init__(self, integration: DatadogIntegration):
        self.integration = integration
        self.api_key = decrypt_value(integration.api_key_encrypted)
        self.app_key = decrypt_value(integration.app_key_encrypted)
        self.base_url = f"https://api.{integration.site}"
        self.last_error = None

    def _get_headers(self) -> Dict:
        """Get headers for API requests."""
        return {
            'DD-API-KEY': self.api_key,
            'DD-APPLICATION-KEY': self.app_key,
            'Content-Type': 'application/json'
        }

    def test_connection(self) -> Dict:
        """Test the Datadog API connection."""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/validate",
                headers=self._get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'API connection successful',
                    'valid': response.json().get('valid', False)
                }
            else:
                return {
                    'success': False,
                    'message': f'API error: {response.status_code}',
                    'error': response.text
                }

        except requests.exceptions.Timeout:
            return {'success': False, 'message': 'Connection timeout'}
        except requests.exceptions.ConnectionError as e:
            return {'success': False, 'message': f'Connection error: {str(e)}'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}

    def get_hosts(self, filter_query: str = None) -> List[Dict]:
        """
        Fetch all hosts from Datadog.

        Args:
            filter_query: Optional Datadog host query filter

        Returns:
            List of host dictionaries
        """
        self.last_error = None
        all_hosts = []
        start = 0
        count = 1000  # Max per request

        try:
            while True:
                params = {
                    'start': start,
                    'count': count,
                    'include_muted_hosts_data': True,
                    'include_hosts_metadata': True
                }

                if filter_query:
                    params['filter'] = filter_query

                response = requests.get(
                    f"{self.base_url}/api/v1/hosts",
                    headers=self._get_headers(),
                    params=params,
                    timeout=30
                )

                if response.status_code != 200:
                    self.last_error = f"API error {response.status_code}: {response.text}"
                    break

                data = response.json()
                hosts = data.get('host_list', [])
                all_hosts.extend(hosts)

                # Check if there are more hosts
                total = data.get('total_matching', 0)
                if start + count >= total:
                    break
                start += count

            return all_hosts

        except Exception as e:
            self.last_error = str(e)
            return []

    def get_host_metrics(self, host_name: str) -> Dict:
        """Get recent metrics for a specific host."""
        try:
            # Get CPU usage
            now = int(datetime.utcnow().timestamp())
            from_time = now - 300  # Last 5 minutes

            metrics = {}

            # System load
            response = requests.get(
                f"{self.base_url}/api/v1/query",
                headers=self._get_headers(),
                params={
                    'from': from_time,
                    'to': now,
                    'query': f'avg:system.load.1{{host:{host_name}}}'
                },
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('series'):
                    points = data['series'][0].get('pointlist', [])
                    if points:
                        metrics['load_avg'] = points[-1][1]

            # CPU usage
            response = requests.get(
                f"{self.base_url}/api/v1/query",
                headers=self._get_headers(),
                params={
                    'from': from_time,
                    'to': now,
                    'query': f'avg:system.cpu.user{{host:{host_name}}} + avg:system.cpu.system{{host:{host_name}}}'
                },
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('series'):
                    points = data['series'][0].get('pointlist', [])
                    if points:
                        metrics['cpu_usage'] = points[-1][1]

            # Memory usage
            response = requests.get(
                f"{self.base_url}/api/v1/query",
                headers=self._get_headers(),
                params={
                    'from': from_time,
                    'to': now,
                    'query': f'avg:system.mem.pct_usable{{host:{host_name}}}'
                },
                timeout=15
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('series'):
                    points = data['series'][0].get('pointlist', [])
                    if points:
                        metrics['memory_usage'] = 100 - (points[-1][1] * 100)  # Convert to usage %

            return metrics

        except Exception as e:
            self.last_error = str(e)
            return {}

    def get_host_tags(self, host_name: str) -> List[str]:
        """Get tags for a specific host."""
        try:
            response = requests.get(
                f"{self.base_url}/api/v1/tags/hosts/{host_name}",
                headers=self._get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                return response.json().get('tags', [])
            return []

        except Exception:
            return []


class DatadogSyncService:
    """Service for syncing Datadog host data to local cache."""

    def __init__(self):
        self.last_error = None

    def sync_integration(self, integration: DatadogIntegration) -> Dict:
        """
        Sync all hosts from a Datadog integration.

        Returns:
            Dict with sync results
        """
        self.last_error = None
        client = DatadogClient(integration)

        result = {
            'integration_id': integration.id,
            'integration_name': integration.name,
            'started_at': datetime.utcnow().isoformat(),
            'success': False,
            'hosts_synced': 0,
            'hosts_added': 0,
            'hosts_updated': 0,
            'hosts_removed': 0,
            'errors': []
        }

        try:
            # Get filter query
            filter_query = integration.filter_query

            # Fetch hosts from Datadog
            hosts = client.get_hosts(filter_query)

            if client.last_error:
                result['errors'].append(client.last_error)
                integration.last_sync = datetime.utcnow()
                integration.last_sync_status = 'failed'
                integration.last_sync_error = client.last_error
                db.session.commit()
                return result

            # Track existing host IDs for cleanup
            existing_ids = set()
            current_dd_host_ids = set()

            # Get existing cached hosts
            existing_hosts = DatadogHostCache.query.filter_by(
                integration_id=integration.id
            ).all()

            for host in existing_hosts:
                existing_ids.add(host.datadog_host_id)

            # Process each host
            for host_data in hosts:
                try:
                    dd_host_id = str(host_data.get('id', host_data.get('host_name', '')))
                    current_dd_host_ids.add(dd_host_id)

                    # Find or create cache entry
                    cache_entry = DatadogHostCache.query.filter_by(
                        integration_id=integration.id,
                        datadog_host_id=dd_host_id
                    ).first()

                    is_new = False
                    if not cache_entry:
                        cache_entry = DatadogHostCache(
                            integration_id=integration.id,
                            datadog_host_id=dd_host_id
                        )
                        is_new = True
                        result['hosts_added'] += 1
                    else:
                        result['hosts_updated'] += 1

                    # Update cache entry
                    cache_entry.host_name = host_data.get('host_name', dd_host_id)
                    cache_entry.aliases = json.dumps(host_data.get('aliases', []))
                    cache_entry.up = host_data.get('up', host_data.get('is_muted', False) is False)

                    # Parse last reported time
                    last_reported = host_data.get('last_reported_time')
                    if last_reported:
                        cache_entry.last_reported = datetime.fromtimestamp(last_reported)

                    # Extract metadata
                    meta = host_data.get('meta', {})
                    gohai = meta.get('gohai', {})

                    # Platform info
                    platform_info = gohai.get('platform', {}) if isinstance(gohai, dict) else {}
                    cache_entry.os_name = platform_info.get('os', meta.get('platform'))
                    cache_entry.platform = platform_info.get('platform', meta.get('processor'))

                    # CPU info
                    cpu_info = gohai.get('cpu', {}) if isinstance(gohai, dict) else {}
                    if isinstance(cpu_info, dict):
                        cache_entry.cpu_cores = cpu_info.get('cpu_cores')

                    # Memory info
                    memory_info = gohai.get('memory', {}) if isinstance(gohai, dict) else {}
                    if isinstance(memory_info, dict):
                        total_mem = memory_info.get('total')
                        if total_mem:
                            # Convert to bytes if it's a string
                            if isinstance(total_mem, str):
                                total_mem = total_mem.replace('kB', '').strip()
                                try:
                                    cache_entry.memory_total = int(total_mem) * 1024
                                except ValueError:
                                    pass
                            else:
                                cache_entry.memory_total = total_mem

                    # Cloud provider info
                    cloud_provider = meta.get('cloud_provider')
                    if cloud_provider:
                        cache_entry.cloud_provider = cloud_provider

                    # AWS-specific
                    if 'aws_id' in host_data:
                        cache_entry.cloud_provider = 'aws'
                        cache_entry.cloud_instance_id = host_data.get('aws_id')

                    # Azure-specific
                    if meta.get('azure_host_id'):
                        cache_entry.cloud_provider = 'azure'
                        cache_entry.cloud_instance_id = meta.get('azure_host_id')

                    # GCP-specific
                    if meta.get('gcp_project_id'):
                        cache_entry.cloud_provider = 'gcp'
                        cache_entry.cloud_instance_id = meta.get('gcp_instance_id')

                    # Tags
                    cache_entry.tags = json.dumps(host_data.get('tags_by_source', host_data.get('tags', [])))

                    # Sources and apps
                    cache_entry.sources = json.dumps(host_data.get('sources', []))
                    cache_entry.apps = json.dumps(host_data.get('apps', []))

                    # Agent info
                    agent_info = meta.get('agent_checks', [])
                    if agent_info:
                        cache_entry.agent_checks = json.dumps(agent_info)

                    agent_version = meta.get('agent_version')
                    if agent_version:
                        cache_entry.agent_version = agent_version

                    # Store raw data
                    cache_entry.raw_data = json.dumps(host_data)
                    cache_entry.meta = json.dumps(meta)
                    cache_entry.cached_at = datetime.utcnow()

                    if is_new:
                        db.session.add(cache_entry)

                    result['hosts_synced'] += 1

                except Exception as e:
                    result['errors'].append(f"Error processing host {host_data.get('host_name', 'unknown')}: {str(e)}")

            # Remove hosts that no longer exist in Datadog
            removed_ids = existing_ids - current_dd_host_ids
            if removed_ids:
                DatadogHostCache.query.filter(
                    DatadogHostCache.integration_id == integration.id,
                    DatadogHostCache.datadog_host_id.in_(removed_ids)
                ).delete(synchronize_session=False)
                result['hosts_removed'] = len(removed_ids)

            # Update integration status
            integration.last_sync = datetime.utcnow()
            integration.last_sync_status = 'success' if not result['errors'] else 'partial'
            integration.last_sync_error = '; '.join(result['errors']) if result['errors'] else None
            integration.last_sync_host_count = result['hosts_synced']

            db.session.commit()
            result['success'] = True
            result['completed_at'] = datetime.utcnow().isoformat()

        except Exception as e:
            self.last_error = str(e)
            result['errors'].append(str(e))
            integration.last_sync = datetime.utcnow()
            integration.last_sync_status = 'failed'
            integration.last_sync_error = str(e)
            db.session.commit()

        return result

    def sync_all_active(self) -> List[Dict]:
        """Sync all active Datadog integrations."""
        results = []
        integrations = DatadogIntegration.query.filter_by(is_active=True).all()

        for integration in integrations:
            result = self.sync_integration(integration)
            results.append(result)

        return results


# Singleton instances
datadog_sync_service = DatadogSyncService()
