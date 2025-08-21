"""
Reconnaissance Agent - Initial target analysis and information gathering
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
import aiohttp
import socket
import ssl
from urllib.parse import urlparse

from .base import BaseAgent
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ReconAgent(BaseAgent):
    """Agent responsible for reconnaissance and target analysis"""
    
    def _get_system_prompt(self) -> str:
        return """You are a reconnaissance specialist AI. Your role is to:
        1. Analyze target infrastructure and technology stack
        2. Identify potential attack surfaces
        3. Discover services, endpoints, and APIs
        4. Map the target's digital footprint
        5. Prioritize areas for deeper investigation"""
    
    async def analyze(self, target: str) -> Dict:
        """Perform reconnaissance on target"""
        logger.info(f"Starting reconnaissance on {target}")
        
        recon_data = {
            'target': target,
            'web_server': None,
            'technologies': [],
            'api_endpoints': [],
            'cloud_provider': None,
            'ssl_info': {},
            'dns_records': [],
            'ports': [],
            'headers': {},
            'cookies': [],
            'subdomains': []
        }
        
        # Parse target URL
        parsed = urlparse(target if target.startswith('http') else f'http://{target}')
        hostname = parsed.hostname or target
        
        # Gather web server info
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{hostname}", timeout=10) as response:
                    recon_data['web_server'] = response.headers.get('Server', 'Unknown')
                    recon_data['headers'] = dict(response.headers)
                    recon_data['cookies'] = [str(c) for c in response.cookies]
        except Exception as e:
            logger.debug(f"Web server detection failed: {e}")
        
        # Check for common API endpoints
        common_endpoints = ['/api', '/v1', '/graphql', '/rest', '/.well-known']
        for endpoint in common_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.head(f"http://{hostname}{endpoint}", timeout=5) as response:
                        if response.status < 400:
                            recon_data['api_endpoints'].append(endpoint)
            except:
                pass
        
        # Detect cloud provider
        recon_data['cloud_provider'] = await self._detect_cloud_provider(hostname)
        
        # Get SSL certificate info
        recon_data['ssl_info'] = await self._get_ssl_info(hostname)
        
        # Technology detection based on headers and responses
        recon_data['technologies'] = self._detect_technologies(recon_data['headers'])
        
        return recon_data
    
    async def _detect_cloud_provider(self, hostname: str) -> Optional[str]:
        """Detect cloud provider from DNS and headers"""
        try:
            ip = socket.gethostbyname(hostname)
            # Simplified cloud detection - in production use IP ranges
            if 'amazonaws' in hostname or '52.' in ip or '54.' in ip:
                return 'aws'
            elif 'azure' in hostname or '40.' in ip or '52.' in ip:
                return 'azure'
            elif 'googleusercontent' in hostname:
                return 'gcp'
        except:
            pass
        return None
    
    async def _get_ssl_info(self, hostname: str) -> Dict:
        """Get SSL certificate information"""
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial': cert['serialNumber']
                    }
        except Exception as e:
            logger.debug(f"SSL info gathering failed: {e}")
        return ssl_info
    
    def _detect_technologies(self, headers: Dict) -> List[str]:
        """Detect technologies from headers"""
        technologies = []
        
        # Check for common technology indicators
        tech_indicators = {
            'X-Powered-By': lambda v: v,
            'Server': lambda v: v.split('/')[0] if '/' in v else v,
            'X-AspNet-Version': lambda v: f'ASP.NET {v}',
            'X-Django': lambda v: 'Django',
            'X-Rails-Version': lambda v: f'Ruby on Rails {v}'
        }
        
        for header, extractor in tech_indicators.items():
            if header in headers:
                tech = extractor(headers[header])
                if tech:
                    technologies.append(tech)
        
        return technologies
    
    async def execute(self, task: Dict) -> Any:
        """Execute reconnaissance task"""
        task_type = task.get('type', 'analyze')
        
        if task_type == 'analyze':
            return await self.analyze(task.get('target'))
        elif task_type == 'deep_scan':
            # Implement deep scanning
            return await self.analyze(task.get('target'))
        else:
            return None