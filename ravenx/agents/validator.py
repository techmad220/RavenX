"""
Validator Agent - Validates and verifies vulnerabilities
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
import hashlib
import time

from .base import BaseAgent
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ValidatorAgent(BaseAgent):
    """Agent responsible for vulnerability validation"""
    
    def _get_system_prompt(self) -> str:
        return """You are a validation specialist AI. Your role is to:
        1. Verify vulnerability authenticity
        2. Eliminate false positives
        3. Confirm exploitability
        4. Assess severity accurately
        5. Provide confidence scores"""
    
    async def validate_vulnerability(self, vulnerability: Dict, evidence: Dict) -> Dict:
        """Validate a vulnerability with evidence"""
        validation_result = {
            'vulnerability': vulnerability,
            'valid': False,
            'confidence': 0.0,
            'false_positive_indicators': [],
            'confirmation_methods': [],
            'severity_adjustment': None
        }
        
        # Check for false positive indicators
        fp_indicators = self._check_false_positives(vulnerability, evidence)
        validation_result['false_positive_indicators'] = fp_indicators
        
        if len(fp_indicators) > 2:
            validation_result['valid'] = False
            validation_result['confidence'] = 0.2
            return validation_result
        
        # Confirm through multiple methods
        confirmations = await self._confirm_vulnerability(vulnerability, evidence)
        validation_result['confirmation_methods'] = confirmations
        
        # Calculate confidence
        confidence = self._calculate_validation_confidence(confirmations, fp_indicators)
        validation_result['confidence'] = confidence
        validation_result['valid'] = confidence > 0.7
        
        # Adjust severity if needed
        if validation_result['valid']:
            validation_result['severity_adjustment'] = self._adjust_severity(
                vulnerability, confidence
            )
        
        return validation_result
    
    def _check_false_positives(self, vuln: Dict, evidence: Dict) -> List[str]:
        """Check for false positive indicators"""
        indicators = []
        
        # Generic error messages
        if evidence.get('response'):
            generic_errors = ['error', 'exception', 'warning', 'notice']
            response_lower = str(evidence['response']).lower()
            if all(err not in response_lower for err in generic_errors):
                if vuln['type'] in ['sqli', 'xss']:
                    indicators.append('No error messages in response')
        
        # Rate limiting
        if evidence.get('response_time_variance', 0) < 0.1:
            indicators.append('Consistent response times (possible rate limiting)')
        
        # WAF detection
        waf_signatures = ['cloudflare', 'akamai', 'incapsula', 'blocked', 'forbidden']
        if any(sig in str(evidence.get('response', '')).lower() for sig in waf_signatures):
            indicators.append('WAF/Security product detected')
        
        # Honeypot indicators
        if evidence.get('too_easy', False):
            indicators.append('Suspiciously easy to exploit')
        
        return indicators
    
    async def _confirm_vulnerability(self, vuln: Dict, evidence: Dict) -> List[Dict]:
        """Confirm vulnerability through multiple methods"""
        confirmations = []
        
        # Time-based confirmation
        if vuln['type'] in ['sqli', 'rce']:
            time_test = self._time_based_validation(evidence)
            if time_test['confirmed']:
                confirmations.append(time_test)
        
        # Content-based confirmation
        content_test = self._content_based_validation(vuln, evidence)
        if content_test['confirmed']:
            confirmations.append(content_test)
        
        # Behavior-based confirmation
        behavior_test = self._behavior_based_validation(vuln, evidence)
        if behavior_test['confirmed']:
            confirmations.append(behavior_test)
        
        return confirmations
    
    def _time_based_validation(self, evidence: Dict) -> Dict:
        """Validate using time-based analysis"""
        result = {
            'method': 'time_based',
            'confirmed': False,
            'details': ''
        }
        
        # Check for time delays
        if evidence.get('time_delay'):
            if evidence['time_delay'] > 4:  # 4+ second delay
                result['confirmed'] = True
                result['details'] = f"Confirmed {evidence['time_delay']}s delay"
        
        return result
    
    def _content_based_validation(self, vuln: Dict, evidence: Dict) -> Dict:
        """Validate using content analysis"""
        result = {
            'method': 'content_based',
            'confirmed': False,
            'details': ''
        }
        
        # Check for specific content indicators
        if vuln['type'] == 'xss':
            if '<script>' in str(evidence.get('response', '')):
                result['confirmed'] = True
                result['details'] = 'XSS payload reflected in response'
        elif vuln['type'] == 'sqli':
            sql_errors = ['sql syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL']
            if any(err in str(evidence.get('response', '')).lower() for err in sql_errors):
                result['confirmed'] = True
                result['details'] = 'SQL error message detected'
        
        return result
    
    def _behavior_based_validation(self, vuln: Dict, evidence: Dict) -> Dict:
        """Validate using behavior analysis"""
        result = {
            'method': 'behavior_based',
            'confirmed': False,
            'details': ''
        }
        
        # Check for behavioral changes
        if evidence.get('status_code_change'):
            result['confirmed'] = True
            result['details'] = 'Status code changed with payload'
        elif evidence.get('response_size_variance', 0) > 0.3:
            result['confirmed'] = True
            result['details'] = 'Significant response size variance'
        
        return result
    
    def _calculate_validation_confidence(self, confirmations: List[Dict], 
                                        fp_indicators: List[str]) -> float:
        """Calculate overall validation confidence"""
        base_confidence = 0.5
        
        # Add confidence for confirmations
        confirmation_boost = len(confirmations) * 0.2
        base_confidence += confirmation_boost
        
        # Reduce confidence for false positive indicators
        fp_penalty = len(fp_indicators) * 0.15
        base_confidence -= fp_penalty
        
        # Ensure within bounds
        return max(0.0, min(1.0, base_confidence))
    
    def _adjust_severity(self, vuln: Dict, confidence: float) -> Optional[str]:
        """Adjust severity based on validation"""
        current_severity = vuln.get('severity', 'medium')
        
        # Downgrade if low confidence
        if confidence < 0.8:
            severity_map = {
                'critical': 'high',
                'high': 'medium',
                'medium': 'low',
                'low': 'info'
            }
            return severity_map.get(current_severity, current_severity)
        
        return None
    
    async def analyze(self, target: str) -> Dict:
        """Analyze target for validation"""
        return {
            'target': target,
            'validation_ready': True
        }
    
    async def execute(self, task: Dict) -> Any:
        """Execute validation task"""
        task_type = task.get('type', 'validate')
        
        if task_type == 'validate':
            return await self.validate_vulnerability(
                task.get('vulnerability', {}),
                task.get('evidence', {})
            )
        else:
            return None