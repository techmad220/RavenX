"""
Canary Hunter Agent - CTF-style vulnerability detection using planted markers
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
import random
import string
import hashlib
import uuid
from datetime import datetime
import re
import base64

from .base import BaseAgent
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class CanaryHunter(BaseAgent):
    """
    AI agent that plants and hunts for canaries (markers) to detect vulnerabilities
    Similar to XBOW's CTF approach
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Canary tracking
        self.planted_canaries = {}
        self.found_canaries = {}
        
        # Canary patterns
        self.canary_types = {
            'file_read': self._generate_file_canary,
            'command_injection': self._generate_cmd_canary,
            'sql_injection': self._generate_sql_canary,
            'xxe': self._generate_xxe_canary,
            'ssrf': self._generate_ssrf_canary,
            'path_traversal': self._generate_path_canary,
            'template_injection': self._generate_template_canary,
            'deserialization': self._generate_deser_canary
        }
        
        # Detection patterns
        self.detection_patterns = self._load_detection_patterns()
        
        logger.info("CanaryHunter agent initialized")
    
    def _get_system_prompt(self) -> str:
        return """You are an advanced security research AI specializing in CTF-style vulnerability detection.
        Your role is to:
        1. Plant canaries (unique markers) in various locations
        2. Craft exploit payloads to retrieve these canaries
        3. Identify successful exploits when canaries are retrieved
        4. Validate vulnerabilities through canary confirmation
        
        Think like a CTF player: be creative, thorough, and systematic in your approach.
        Always prioritize safety and avoid causing damage to target systems."""
    
    def _generate_unique_canary(self, prefix: str = "RAVENX") -> str:
        """Generate a unique canary marker"""
        unique_id = str(uuid.uuid4()).replace('-', '')[:8]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        canary = f"{prefix}_{timestamp}_{unique_id}_{random_str}"
        
        # Store canary metadata
        canary_hash = hashlib.sha256(canary.encode()).hexdigest()[:16]
        
        return canary, canary_hash
    
    def _generate_file_canary(self) -> Tuple[str, Dict]:
        """Generate file read canary"""
        canary, hash_val = self._generate_unique_canary("FILERD")
        
        return canary, {
            'type': 'file_read',
            'content': f"<!-- {canary} -->",
            'paths': [
                f"/tmp/{canary}.txt",
                f"/var/tmp/{canary}.log",
                f"/etc/{canary}.conf"
            ],
            'hash': hash_val
        }
    
    def _generate_cmd_canary(self) -> Tuple[str, Dict]:
        """Generate command injection canary"""
        canary, hash_val = self._generate_unique_canary("CMDEXE")
        
        return canary, {
            'type': 'command_injection',
            'commands': [
                f"echo {canary}",
                f"cat /tmp/{canary}",
                f"printenv {canary}_VAR"
            ],
            'env_var': f"{canary}_VAR",
            'hash': hash_val
        }
    
    def _generate_sql_canary(self) -> Tuple[str, Dict]:
        """Generate SQL injection canary"""
        canary, hash_val = self._generate_unique_canary("SQLINJ")
        
        return canary, {
            'type': 'sql_injection',
            'table': f"canary_{hash_val}",
            'column': 'marker',
            'value': canary,
            'queries': [
                f"SELECT '{canary}' as marker",
                f"UNION SELECT '{canary}'",
                f"' OR '1'='1' AND marker='{canary}'"
            ],
            'hash': hash_val
        }
    
    def _generate_xxe_canary(self) -> Tuple[str, Dict]:
        """Generate XXE canary"""
        canary, hash_val = self._generate_unique_canary("XXEEXP")
        
        return canary, {
            'type': 'xxe',
            'file_path': f"/tmp/{canary}.xml",
            'content': f"<canary>{canary}</canary>",
            'dtd': f"""<!DOCTYPE foo [
                <!ENTITY xxe SYSTEM "file:///tmp/{canary}.xml">
            ]>""",
            'hash': hash_val
        }
    
    def _generate_ssrf_canary(self) -> Tuple[str, Dict]:
        """Generate SSRF canary"""
        canary, hash_val = self._generate_unique_canary("SSRFEX")
        
        return canary, {
            'type': 'ssrf',
            'endpoints': [
                f"http://internal.ravenx/{canary}",
                f"http://169.254.169.254/{canary}",
                f"http://localhost:8080/{canary}"
            ],
            'headers': {
                'X-Canary-Token': canary,
                'X-Forwarded-For': f"canary.{canary}.ravenx"
            },
            'hash': hash_val
        }
    
    def _generate_path_canary(self) -> Tuple[str, Dict]:
        """Generate path traversal canary"""
        canary, hash_val = self._generate_unique_canary("PATHTR")
        
        return canary, {
            'type': 'path_traversal',
            'file_name': f"{canary}.txt",
            'paths': [
                f"../../../tmp/{canary}.txt",
                f"..\\..\\..\\windows\\temp\\{canary}.txt",
                f"....//....//....//tmp//{canary}.txt"
            ],
            'content': f"CANARY_CONTENT:{canary}",
            'hash': hash_val
        }
    
    def _generate_template_canary(self) -> Tuple[str, Dict]:
        """Generate template injection canary"""
        canary, hash_val = self._generate_unique_canary("TMPINJ")
        
        return canary, {
            'type': 'template_injection',
            'payloads': [
                f"{{{{ '{canary}' }}}}",
                f"${{'{canary}'}}",
                f"<%= '{canary}' %>",
                f"#set($canary = '{canary}')$canary"
            ],
            'hash': hash_val
        }
    
    def _generate_deser_canary(self) -> Tuple[str, Dict]:
        """Generate deserialization canary"""
        canary, hash_val = self._generate_unique_canary("DESER")
        
        # Base64 encoded payload
        payload = base64.b64encode(f"O:8:\"Canary\":1:{{s:5:\"value\";s:{len(canary)}:\"{canary}\";}}".encode()).decode()
        
        return canary, {
            'type': 'deserialization',
            'payload': payload,
            'raw': canary,
            'hash': hash_val
        }
    
    def _load_detection_patterns(self) -> Dict:
        """Load patterns for detecting retrieved canaries"""
        return {
            'direct_match': re.compile(r'(RAVENX_\d{14}_[a-f0-9]{8}_[A-Z0-9]{6})'),
            'encoded_base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex_encoded': re.compile(r'[0-9a-fA-F]{32,}'),
            'url_encoded': re.compile(r'%[0-9a-fA-F]{2}'),
            'html_encoded': re.compile(r'&\w+;'),
            'json_value': re.compile(r'"([^"]*RAVENX[^"]*)"'),
            'xml_value': re.compile(r'<[^>]*>([^<]*RAVENX[^<]*)</[^>]*>')
        }
    
    async def plant_canaries(self, target: str, vulnerability_types: List[str]) -> Dict:
        """
        Plant canaries for specified vulnerability types
        """
        planted = {}
        
        for vuln_type in vulnerability_types:
            if vuln_type in self.canary_types:
                canary, metadata = self.canary_types[vuln_type]()
                
                # Store planted canary
                self.planted_canaries[canary] = {
                    'target': target,
                    'metadata': metadata,
                    'planted_at': datetime.now().isoformat(),
                    'found': False
                }
                
                planted[vuln_type] = {
                    'canary': canary,
                    'metadata': metadata
                }
                
                logger.debug(f"Planted {vuln_type} canary: {canary[:20]}...")
        
        return planted
    
    async def hunt_canary(self, response: str, context: Dict = None) -> List[Dict]:
        """
        Hunt for planted canaries in response data
        """
        found_canaries = []
        
        # Check for direct matches
        for pattern_name, pattern in self.detection_patterns.items():
            matches = pattern.findall(response)
            
            for match in matches:
                # Check if it's a planted canary
                for canary, canary_data in self.planted_canaries.items():
                    if canary in str(match) or str(match) in canary:
                        found_canaries.append({
                            'canary': canary,
                            'pattern': pattern_name,
                            'match': match,
                            'context': context,
                            'vulnerability_type': canary_data['metadata']['type'],
                            'confidence': self._calculate_confidence(pattern_name, match, canary)
                        })
                        
                        # Mark as found
                        self.planted_canaries[canary]['found'] = True
                        self.planted_canaries[canary]['found_at'] = datetime.now().isoformat()
                        
                        logger.info(f"Canary found! Type: {canary_data['metadata']['type']}, "
                                  f"Pattern: {pattern_name}")
        
        # Try decoding potential encoded canaries
        decoded_canaries = await self._hunt_encoded_canaries(response)
        found_canaries.extend(decoded_canaries)
        
        return found_canaries
    
    async def _hunt_encoded_canaries(self, response: str) -> List[Dict]:
        """
        Hunt for encoded canaries
        """
        found = []
        
        # Try base64 decoding
        try:
            potential_b64 = self.detection_patterns['encoded_base64'].findall(response)
            for b64_str in potential_b64:
                try:
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    canary_matches = await self.hunt_canary(decoded, {'encoding': 'base64'})
                    found.extend(canary_matches)
                except:
                    pass
        except:
            pass
        
        # Try hex decoding
        try:
            potential_hex = self.detection_patterns['hex_encoded'].findall(response)
            for hex_str in potential_hex:
                try:
                    decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                    canary_matches = await self.hunt_canary(decoded, {'encoding': 'hex'})
                    found.extend(canary_matches)
                except:
                    pass
        except:
            pass
        
        return found
    
    def _calculate_confidence(self, pattern: str, match: str, canary: str) -> float:
        """
        Calculate confidence score for found canary
        """
        confidence = 0.5  # Base confidence
        
        # Exact match
        if match == canary:
            confidence = 1.0
        # Partial match
        elif canary in match or match in canary:
            confidence = 0.8
        
        # Adjust based on pattern type
        pattern_confidence = {
            'direct_match': 1.0,
            'json_value': 0.9,
            'xml_value': 0.9,
            'encoded_base64': 0.7,
            'hex_encoded': 0.7,
            'url_encoded': 0.6,
            'html_encoded': 0.6
        }
        
        if pattern in pattern_confidence:
            confidence *= pattern_confidence[pattern]
        
        return min(confidence, 1.0)
    
    async def generate_exploit_payload(self, vuln_type: str, canary_data: Dict) -> List[str]:
        """
        Generate exploit payloads to retrieve canaries
        """
        prompt = f"""Generate exploit payloads for {vuln_type} vulnerability.
        Target canary: {canary_data.get('canary', 'unknown')}
        Canary location/context: {json.dumps(canary_data.get('metadata', {}), indent=2)}
        
        Create multiple payload variations that could retrieve this canary.
        Focus on safe, non-destructive payloads."""
        
        response = await self.think(prompt, {'vulnerability_type': vuln_type})
        
        # Parse response to extract payloads
        payloads = self._parse_payloads(response)
        
        return payloads
    
    def _parse_payloads(self, response: str) -> List[str]:
        """Parse AI response to extract payloads"""
        payloads = []
        
        # Look for code blocks
        code_blocks = re.findall(r'```[^\n]*\n(.*?)```', response, re.DOTALL)
        payloads.extend(code_blocks)
        
        # Look for quoted strings
        quoted = re.findall(r'"([^"]+)"', response)
        payloads.extend(quoted)
        
        # Look for single-quoted strings
        single_quoted = re.findall(r"'([^']+)'", response)
        payloads.extend(single_quoted)
        
        return payloads
    
    async def analyze(self, target: str) -> Dict:
        """
        Analyze target for canary planting opportunities
        """
        analysis = {
            'target': target,
            'suitable_canary_types': [],
            'planting_strategy': {},
            'risk_assessment': {}
        }
        
        # Determine suitable canary types based on target
        prompt = f"""Analyze the target {target} and determine:
        1. What types of vulnerabilities are most likely
        2. Where canaries should be planted
        3. What canary types would be most effective
        
        Consider: file read, command injection, SQL injection, XXE, SSRF, path traversal, template injection, deserialization"""
        
        response = await self.think(prompt)
        
        # Parse response and update analysis
        # This would be more sophisticated in production
        analysis['suitable_canary_types'] = list(self.canary_types.keys())
        
        return analysis
    
    async def execute(self, task: Dict) -> Any:
        """
        Execute canary hunting task
        """
        task_type = task.get('type')
        
        if task_type == 'plant':
            return await self.plant_canaries(
                task.get('target'),
                task.get('vulnerability_types', list(self.canary_types.keys()))
            )
        elif task_type == 'hunt':
            return await self.hunt_canary(
                task.get('response', ''),
                task.get('context')
            )
        elif task_type == 'generate_payload':
            return await self.generate_exploit_payload(
                task.get('vuln_type'),
                task.get('canary_data')
            )
        else:
            logger.warning(f"Unknown task type: {task_type}")
            return None
    
    def get_statistics(self) -> Dict:
        """Get canary hunting statistics"""
        total_planted = len(self.planted_canaries)
        total_found = sum(1 for c in self.planted_canaries.values() if c['found'])
        
        by_type = {}
        for canary, data in self.planted_canaries.items():
            vuln_type = data['metadata']['type']
            if vuln_type not in by_type:
                by_type[vuln_type] = {'planted': 0, 'found': 0}
            by_type[vuln_type]['planted'] += 1
            if data['found']:
                by_type[vuln_type]['found'] += 1
        
        return {
            'total_planted': total_planted,
            'total_found': total_found,
            'success_rate': (total_found / total_planted * 100) if total_planted > 0 else 0,
            'by_type': by_type
        }