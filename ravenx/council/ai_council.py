"""
AI Council - Board of Council approach for multi-model consensus decision making
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
import json
import numpy as np
from datetime import datetime
import hashlib
from collections import Counter

from ..utils.logger import setup_logger
from ..agents.base import BaseAgent

logger = setup_logger(__name__)

class CouncilRole(Enum):
    """Roles for council members"""
    ATTACKER = "attacker"          # Offensive security mindset
    DEFENDER = "defender"          # Defensive security perspective  
    ANALYST = "analyst"            # Data analysis and pattern recognition
    VALIDATOR = "validator"        # Verification and false positive detection
    STRATEGIST = "strategist"      # High-level planning and prioritization
    SPECIALIST = "specialist"      # Domain-specific expertise
    AUDITOR = "auditor"           # Compliance and risk assessment
    INNOVATOR = "innovator"       # Creative and unconventional approaches
    CODE_AUDITOR = "code_auditor"  # Source code vulnerability analysis
    EXPLOIT_DEV = "exploit_dev"    # Exploit development and PoC creation
    THREAT_INTEL = "threat_intel"  # Threat intelligence and CVE analysis
    REVERSE_ENG = "reverse_eng"    # Reverse engineering and binary analysis
    CLOUD_SEC = "cloud_sec"        # Cloud security specialist
    API_SEC = "api_sec"            # API security specialist
    CRYPTO_ANALYST = "crypto_analyst" # Cryptography and authentication
    NETWORK_SEC = "network_sec"    # Network security and protocols

class CouncilMember:
    """Individual AI council member with specific role and model"""
    
    def __init__(self, name: str, role: CouncilRole, model_config: Dict):
        self.name = name
        self.role = role
        self.model_config = model_config
        self.model_type = model_config.get('type')  # openai, anthropic, llama, mistral, etc.
        self.model_name = model_config.get('model')
        self.temperature = model_config.get('temperature', 0.7)
        self.expertise_areas = model_config.get('expertise', [])
        
        # Track member performance
        self.votes_cast = 0
        self.correct_votes = 0
        self.influence_score = 1.0
        
        # Initialize the agent
        self.agent = self._initialize_agent()
        
        logger.debug(f"Council member {name} ({role.value}) initialized with {self.model_type}")
    
    def _initialize_agent(self):
        """Initialize the underlying AI agent"""
        from ..agents.council_agent import CouncilAgent
        return CouncilAgent({
            'name': self.name,
            'role': self.role.value,
            'ai_provider': self.model_type,
            f'{self.model_type}_model': self.model_name,
            f'{self.model_type}_api_key': self.model_config.get('api_key'),
            'temperature': self.temperature,
            'system_prompt': self._get_role_prompt()
        })
    
    def _get_role_prompt(self) -> str:
        """Get role-specific system prompt"""
        prompts = {
            CouncilRole.ATTACKER: """You are an offensive security expert on the AI Council.
                Your role is to think like an attacker and identify exploitation opportunities.
                Focus on: attack vectors, exploit chains, bypasses, and offensive techniques.
                Be creative and thorough in finding vulnerabilities.""",
            
            CouncilRole.DEFENDER: """You are a defensive security expert on the AI Council.
                Your role is to evaluate security from a defender's perspective.
                Focus on: detection methods, false positives, impact assessment, and mitigation.
                Be skeptical and ensure findings are legitimate.""",
            
            CouncilRole.ANALYST: """You are a security analyst on the AI Council.
                Your role is to analyze patterns and data to identify vulnerabilities.
                Focus on: data correlation, pattern recognition, statistical analysis, and trends.
                Use evidence-based reasoning and data-driven decisions.""",
            
            CouncilRole.VALIDATOR: """You are a validation expert on the AI Council.
                Your role is to verify and validate security findings.
                Focus on: proof of concept, reproducibility, false positive detection, and accuracy.
                Be rigorous in testing and confirming vulnerabilities.""",
            
            CouncilRole.STRATEGIST: """You are a strategic advisor on the AI Council.
                Your role is to provide high-level guidance and prioritization.
                Focus on: risk assessment, impact analysis, resource allocation, and strategy.
                Think holistically about security objectives.""",
            
            CouncilRole.SPECIALIST: """You are a domain specialist on the AI Council.
                Your role is to provide deep expertise in specific vulnerability types.
                Focus on: technical details, edge cases, advanced techniques, and specialized knowledge.
                Apply your domain expertise to identify subtle vulnerabilities.""",
            
            CouncilRole.AUDITOR: """You are a security auditor on the AI Council.
                Your role is to ensure compliance and assess risk.
                Focus on: standards compliance, risk metrics, audit trails, and documentation.
                Maintain objectivity and thoroughness in assessments.""",
            
            CouncilRole.INNOVATOR: """You are an innovation expert on the AI Council.
                Your role is to think outside the box and find novel vulnerabilities.
                Focus on: unconventional approaches, zero-days, logic flaws, and creative exploitation.
                Challenge assumptions and explore new attack surfaces.""",
            
            CouncilRole.CODE_AUDITOR: """You are a source code security auditor on the AI Council.
                Your role is to analyze source code for security vulnerabilities.
                Focus on: code injection, buffer overflows, race conditions, unsafe functions, and coding antipatterns.
                Review code with attention to detail and security best practices.""",
            
            CouncilRole.EXPLOIT_DEV: """You are an exploit developer on the AI Council.
                Your role is to create working exploits and proof-of-concepts.
                Focus on: shellcode, ROP chains, heap spraying, ASLR bypass, and reliable exploitation.
                Develop clean, weaponized exploits that demonstrate real impact.""",
            
            CouncilRole.THREAT_INTEL: """You are a threat intelligence analyst on the AI Council.
                Your role is to analyze threats, CVEs, and attack patterns.
                Focus on: CVE analysis, threat actors, TTPs, vulnerability trends, and emerging threats.
                Provide context on real-world exploitation and threat landscape.""",
            
            CouncilRole.REVERSE_ENG: """You are a reverse engineering specialist on the AI Council.
                Your role is to analyze binaries and compiled code for vulnerabilities.
                Focus on: binary analysis, decompilation, protocol reverse engineering, and firmware analysis.
                Uncover hidden vulnerabilities in compiled applications.""",
            
            CouncilRole.CLOUD_SEC: """You are a cloud security specialist on the AI Council.
                Your role is to identify cloud-specific vulnerabilities.
                Focus on: misconfigurations, IAM issues, serverless vulnerabilities, container security, and cloud services.
                Expertise in AWS, Azure, GCP, and cloud-native technologies.""",
            
            CouncilRole.API_SEC: """You are an API security specialist on the AI Council.
                Your role is to identify API vulnerabilities and design flaws.
                Focus on: REST/GraphQL security, authentication bypasses, rate limiting, IDOR, and API abuse.
                Understand modern API architectures and microservices.""",
            
            CouncilRole.CRYPTO_ANALYST: """You are a cryptography analyst on the AI Council.
                Your role is to identify cryptographic weaknesses and authentication flaws.
                Focus on: weak encryption, poor key management, authentication bypasses, and crypto implementation flaws.
                Deep understanding of cryptographic protocols and common mistakes.""",
            
            CouncilRole.NETWORK_SEC: """You are a network security specialist on the AI Council.
                Your role is to identify network protocol and infrastructure vulnerabilities.
                Focus on: protocol weaknesses, man-in-the-middle, DNS issues, routing attacks, and network segmentation.
                Expert in TCP/IP, TLS, and network protocols."""
        }
        
        return prompts.get(self.role, "You are a security expert on the AI Council.")
    
    async def deliberate(self, topic: str, context: Dict) -> Dict:
        """Member deliberates on a topic and provides their assessment"""
        response = await self.agent.think(topic, context)
        
        return {
            'member': self.name,
            'role': self.role.value,
            'assessment': response,
            'confidence': self._calculate_confidence(response),
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_confidence(self, response: str) -> float:
        """Calculate confidence score based on response characteristics"""
        # Simplified confidence calculation
        confidence = 0.5
        
        # Check for certainty indicators
        high_confidence_terms = ['definitely', 'certainly', 'confirmed', 'verified', 'clear']
        low_confidence_terms = ['possibly', 'maybe', 'might', 'could', 'uncertain']
        
        response_lower = response.lower()
        
        for term in high_confidence_terms:
            if term in response_lower:
                confidence += 0.1
        
        for term in low_confidence_terms:
            if term in response_lower:
                confidence -= 0.1
        
        # Adjust based on member's historical performance
        if self.votes_cast > 10:
            accuracy = self.correct_votes / self.votes_cast
            confidence *= (0.5 + accuracy * 0.5)
        
        return max(0.1, min(1.0, confidence))
    
    def update_performance(self, was_correct: bool):
        """Update member's performance metrics"""
        self.votes_cast += 1
        if was_correct:
            self.correct_votes += 1
        
        # Update influence score
        if self.votes_cast > 5:
            self.influence_score = 0.5 + (self.correct_votes / self.votes_cast) * 0.5

class AICouncil:
    """
    Board of AI models that collaborate to make security decisions
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.members = []
        self.session_id = None
        
        # Decision tracking
        self.decisions = []
        self.consensus_threshold = config.get('consensus_threshold', 0.7)
        
        # Initialize council members
        self._initialize_council()
        
        logger.info(f"AI Council initialized with {len(self.members)} members")
    
    async def _turn_based_deliberation(self, topic: str, context: Dict) -> List[Dict]:
        """
        Turn-based deliberation where each member considers previous responses
        """
        deliberations = []
        accumulated_context = context.copy()
        
        # Sort members by role priority for turn order
        role_priority = {
            CouncilRole.ANALYST: 1,  # Analysts go first to provide data
            CouncilRole.THREAT_INTEL: 2,  # Threat intel provides context
            CouncilRole.CODE_AUDITOR: 3,  # Code auditors examine specifics
            CouncilRole.REVERSE_ENG: 4,  # Reverse engineers dive deep
            CouncilRole.ATTACKER: 5,  # Attackers identify exploits
            CouncilRole.EXPLOIT_DEV: 6,  # Exploit devs create PoCs
            CouncilRole.DEFENDER: 7,  # Defenders assess defenses
            CouncilRole.VALIDATOR: 8,  # Validators verify findings
            CouncilRole.SPECIALIST: 9,  # Specialists add domain expertise
            CouncilRole.CLOUD_SEC: 10,
            CouncilRole.API_SEC: 11,
            CouncilRole.NETWORK_SEC: 12,
            CouncilRole.CRYPTO_ANALYST: 13,
            CouncilRole.INNOVATOR: 14,  # Innovators think outside the box
            CouncilRole.AUDITOR: 15,  # Auditors assess compliance
            CouncilRole.STRATEGIST: 16,  # Strategists make final recommendations
        }
        
        sorted_members = sorted(self.members, 
                              key=lambda m: role_priority.get(m.role, 99))
        
        logger.info(f"Turn-based order: {[m.name for m in sorted_members]}")
        
        for i, member in enumerate(sorted_members):
            # Add previous deliberations to context
            if deliberations:
                accumulated_context['previous_assessments'] = [
                    {
                        'member': d['member'],
                        'role': d['role'],
                        'key_points': d['assessment'][:200]  # Summary only
                    }
                    for d in deliberations[-3:]  # Last 3 assessments for context
                ]
                
                # Enhanced prompt for turn-based
                enhanced_topic = f"""{topic}
                
                Previous council members have provided their assessments.
                As {member.role.value}, consider their input and provide your unique perspective.
                Build upon or challenge previous assessments as appropriate."""
            else:
                enhanced_topic = topic
            
            # Member deliberates with accumulated context
            logger.debug(f"Turn {i+1}: {member.name} ({member.role.value}) deliberating...")
            
            deliberation = await member.deliberate(enhanced_topic, accumulated_context)
            deliberations.append(deliberation)
            
            # Add this member's assessment to context for next member
            accumulated_context[f'assessment_{member.role.value}'] = deliberation['assessment'][:500]
            
            logger.debug(f"{member.name} completed deliberation")
        
        return deliberations
    
    def _initialize_council(self):
        """Initialize council members with diverse models and roles"""
        
        # Default council configuration with multiple AI models (16 members)
        default_members = [
            # Core Security Council (8 members)
            {
                'name': 'Alpha-GPT4',
                'role': CouncilRole.ATTACKER,
                'config': {
                    'type': 'openai',
                    'model': 'gpt-4-turbo-preview',
                    'temperature': 0.8,
                    'expertise': ['web', 'api', 'injection']
                }
            },
            {
                'name': 'Beta-Claude',
                'role': CouncilRole.DEFENDER,
                'config': {
                    'type': 'anthropic',
                    'model': 'claude-3-haiku-20240307',  # Fast medium model
                    'temperature': 0.6,
                    'expertise': ['defense', 'detection', 'mitigation']
                }
            },
            {
                'name': 'Gamma-DeepSeekCoder',
                'role': CouncilRole.CODE_AUDITOR,
                'config': {
                    'type': 'deepseek',
                    'model': 'deepseek-coder-33b-instruct',  # DeepSeek's code specialist
                    'temperature': 0.5,
                    'expertise': ['code', 'vulnerabilities', 'static-analysis']
                }
            },
            {
                'name': 'Delta-CodeLlama',
                'role': CouncilRole.EXPLOIT_DEV,
                'config': {
                    'type': 'meta',
                    'model': 'codellama-70b-instruct',  # Meta's largest Code Llama
                    'temperature': 0.7,
                    'expertise': ['exploits', 'poc', 'shellcode']
                }
            },
            {
                'name': 'Epsilon-GLM45',
                'role': CouncilRole.ANALYST,
                'config': {
                    'type': 'zhipu',
                    'model': 'glm-4.5',  # GLM-4.5 from Zhipu AI
                    'temperature': 0.5,
                    'expertise': ['patterns', 'anomalies', 'correlation']
                }
            },
            {
                'name': 'Zeta-Mixtral',
                'role': CouncilRole.SPECIALIST,
                'config': {
                    'type': 'mistral',
                    'model': 'mixtral-8x7b-instruct',  # MoE architecture
                    'temperature': 0.6,
                    'expertise': ['technical', 'infrastructure', 'protocols']
                }
            },
            {
                'name': 'Eta-Gemini',
                'role': CouncilRole.VALIDATOR,
                'config': {
                    'type': 'google',
                    'model': 'gemini-1.5-flash',  # Fast validation
                    'temperature': 0.3,
                    'expertise': ['validation', 'verification', 'testing']
                }
            },
            {
                'name': 'Theta-GPTNeoX',
                'role': CouncilRole.INNOVATOR,
                'config': {
                    'type': 'eleutherai',
                    'model': 'gpt-neox-20b',  # EleutherAI GPT-NeoX 20B open source
                    'temperature': 0.9,
                    'expertise': ['creative', 'zero-day', 'novel']
                }
            },
            
            # Specialized Security Council (9 additional members with GPT-OSS)
            {
                'name': 'Iota-WizardCoder',
                'role': CouncilRole.CODE_AUDITOR,
                'config': {
                    'type': 'wizardlm',
                    'model': 'wizardcoder-33b',  # Code security specialist
                    'temperature': 0.4,
                    'expertise': ['secure-coding', 'SAST', 'code-review']
                }
            },
            {
                'name': 'Kappa-Phind',
                'role': CouncilRole.API_SEC,
                'config': {
                    'type': 'phind',
                    'model': 'phind-codellama-34b',  # API and web specialist
                    'temperature': 0.5,
                    'expertise': ['api', 'rest', 'graphql', 'websocket']
                }
            },
            {
                'name': 'Lambda-Qwen',
                'role': CouncilRole.CLOUD_SEC,
                'config': {
                    'type': 'alibaba',
                    'model': 'qwen-14b',  # Cloud infrastructure
                    'temperature': 0.6,
                    'expertise': ['cloud', 'kubernetes', 'serverless']
                }
            },
            {
                'name': 'Mu-StarCoder',
                'role': CouncilRole.REVERSE_ENG,
                'config': {
                    'type': 'huggingface',
                    'model': 'starcoder-15b',  # Binary and code analysis
                    'temperature': 0.5,
                    'expertise': ['binary', 'reverse', 'malware']
                }
            },
            {
                'name': 'Nu-Falcon',
                'role': CouncilRole.THREAT_INTEL,
                'config': {
                    'type': 'tii',
                    'model': 'falcon-40b',  # Threat intelligence
                    'temperature': 0.4,
                    'expertise': ['cve', 'threats', 'apt', 'ioc']
                }
            },
            {
                'name': 'Xi-Yi',
                'role': CouncilRole.NETWORK_SEC,
                'config': {
                    'type': '01ai',
                    'model': 'yi-34b',  # Network protocols
                    'temperature': 0.5,
                    'expertise': ['network', 'protocols', 'pcap', 'ids']
                }
            },
            {
                'name': 'Omicron-CyberSecEval',
                'role': CouncilRole.CRYPTO_ANALYST,
                'config': {
                    'type': 'meta',
                    'model': 'cyberseceval-llama3-70b',  # Meta's cybersecurity-trained model
                    'temperature': 0.3,
                    'expertise': ['crypto', 'auth', 'certificates', 'tls', 'cyberattacks']
                }
            },
            {
                'name': 'Pi-Claude-Instant',
                'role': CouncilRole.STRATEGIST,
                'config': {
                    'type': 'anthropic',
                    'model': 'claude-instant-1.2',  # Fast strategy decisions
                    'temperature': 0.6,
                    'expertise': ['strategy', 'risk', 'prioritization']
                }
            },
            {
                'name': 'Rho-GPTOSS',
                'role': CouncilRole.SPECIALIST,
                'config': {
                    'type': 'opensource',
                    'model': 'gpt-oss-20b',  # Open source GPT 20B model
                    'temperature': 0.7,
                    'expertise': ['general-security', 'vulnerability-research', 'open-source']
                }
            }
        ]
        
        # Use custom configuration if provided, otherwise use defaults
        member_configs = self.config.get('council_members', default_members)
        
        for member_config in member_configs:
            member = CouncilMember(
                name=member_config['name'],
                role=member_config['role'],
                model_config=member_config['config']
            )
            self.members.append(member)
            
            # Add API keys from main config if not in member config
            if 'api_key' not in member.model_config:
                if member.model_type == 'openai':
                    member.model_config['api_key'] = self.config.get('openai_api_key')
                elif member.model_type == 'anthropic':
                    member.model_config['api_key'] = self.config.get('anthropic_api_key')
    
    async def convene(self, topic: str, context: Dict = None, mode: str = "turn_based") -> Dict:
        """
        Convene the council to deliberate on a security topic
        
        Args:
            topic: The security issue to discuss
            context: Additional context for the deliberation
            mode: "turn_based" for sequential or "parallel" for simultaneous
        
        Returns:
            Council decision with consensus and individual assessments
        """
        session_id = hashlib.md5(f"{topic}{datetime.now()}".encode()).hexdigest()[:8]
        
        logger.info(f"Council convening - Session {session_id}: {topic[:50]}...")
        logger.info(f"Deliberation mode: {mode}")
        
        if mode == "turn_based":
            # Turn-based deliberation where each member considers previous responses
            deliberations = await self._turn_based_deliberation(topic, context or {})
        else:
            # Parallel deliberation by all members (original implementation)
            deliberation_tasks = []
            for member in self.members:
                task = asyncio.create_task(member.deliberate(topic, context or {}))
                deliberation_tasks.append(task)
            
            # Collect all deliberations
            deliberations = await asyncio.gather(*deliberation_tasks)
        
        # Analyze deliberations and reach consensus
        consensus = await self._reach_consensus(deliberations, topic)
        
        # Record decision
        decision = {
            'session_id': session_id,
            'topic': topic,
            'timestamp': datetime.now().isoformat(),
            'deliberations': deliberations,
            'consensus': consensus,
            'decision': self._make_decision(consensus),
            'confidence': self._calculate_council_confidence(deliberations)
        }
        
        self.decisions.append(decision)
        
        logger.info(f"Council decision - Session {session_id}: {decision['decision']['verdict']}")
        
        return decision
    
    async def _reach_consensus(self, deliberations: List[Dict], topic: str) -> Dict:
        """
        Analyze deliberations to reach consensus
        """
        # Extract key points from each deliberation
        key_points = []
        sentiments = []
        
        for delib in deliberations:
            assessment = delib['assessment']
            
            # Simple sentiment analysis (in production, use proper NLP)
            if any(word in assessment.lower() for word in ['vulnerable', 'exploit', 'risk', 'danger']):
                sentiments.append('vulnerable')
            elif any(word in assessment.lower() for word in ['safe', 'secure', 'protected', 'mitigated']):
                sentiments.append('secure')
            else:
                sentiments.append('uncertain')
            
            # Extract confidence-weighted vote
            confidence = delib['confidence']
            member_role = delib['role']
            
            # Role-based weight adjustment
            role_weights = {
                'attacker': 1.2,
                'defender': 1.1,
                'validator': 1.3,
                'analyst': 1.0,
                'strategist': 0.9,
                'specialist': 1.1,
                'auditor': 1.0,
                'innovator': 0.8
            }
            
            weight = role_weights.get(member_role, 1.0)
            
            key_points.append({
                'member': delib['member'],
                'sentiment': sentiments[-1],
                'confidence': confidence,
                'weight': weight,
                'weighted_confidence': confidence * weight
            })
        
        # Calculate consensus
        sentiment_counts = Counter(sentiments)
        majority_sentiment = sentiment_counts.most_common(1)[0][0]
        
        # Calculate weighted consensus score
        total_weight = sum(kp['weighted_confidence'] for kp in key_points)
        vulnerable_weight = sum(
            kp['weighted_confidence'] for kp in key_points 
            if kp['sentiment'] == 'vulnerable'
        )
        
        consensus_score = vulnerable_weight / total_weight if total_weight > 0 else 0.5
        
        return {
            'sentiment': majority_sentiment,
            'score': consensus_score,
            'agreement_level': self._calculate_agreement(sentiments),
            'key_points': key_points,
            'dissenting_opinions': [
                kp for kp in key_points 
                if kp['sentiment'] != majority_sentiment
            ]
        }
    
    def _calculate_agreement(self, sentiments: List[str]) -> float:
        """Calculate level of agreement among council members"""
        if not sentiments:
            return 0.0
        
        counts = Counter(sentiments)
        majority_count = counts.most_common(1)[0][1]
        
        return majority_count / len(sentiments)
    
    def _make_decision(self, consensus: Dict) -> Dict:
        """
        Make final decision based on consensus
        """
        score = consensus['score']
        agreement = consensus['agreement_level']
        
        # Decision logic
        if score > 0.7 and agreement > 0.6:
            verdict = 'confirmed_vulnerable'
            action = 'exploit_and_report'
        elif score > 0.5 and agreement > 0.5:
            verdict = 'likely_vulnerable'
            action = 'investigate_further'
        elif score < 0.3 and agreement > 0.6:
            verdict = 'not_vulnerable'
            action = 'skip'
        else:
            verdict = 'uncertain'
            action = 'request_human_review'
        
        return {
            'verdict': verdict,
            'action': action,
            'score': score,
            'agreement': agreement,
            'requires_validation': score > 0.3
        }
    
    def _calculate_council_confidence(self, deliberations: List[Dict]) -> float:
        """Calculate overall council confidence"""
        if not deliberations:
            return 0.0
        
        confidences = [d['confidence'] for d in deliberations]
        
        # Use weighted average with penalty for high variance
        mean_confidence = np.mean(confidences)
        std_confidence = np.std(confidences)
        
        # Penalize disagreement
        adjusted_confidence = mean_confidence * (1 - std_confidence * 0.5)
        
        return max(0.1, min(1.0, adjusted_confidence))
    
    async def vote_on_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Council votes on whether a finding is a valid vulnerability
        """
        topic = f"""Evaluate this potential vulnerability:
        Type: {vulnerability.get('type')}
        Severity: {vulnerability.get('severity')}
        Description: {vulnerability.get('description')}
        Evidence: {vulnerability.get('evidence')}
        
        Is this a valid, exploitable vulnerability that should be reported?"""
        
        context = {
            'vulnerability': vulnerability,
            'target': vulnerability.get('target'),
            'confidence': vulnerability.get('confidence', 0)
        }
        
        decision = await self.convene(topic, context)
        
        return decision
    
    async def prioritize_targets(self, targets: List[str]) -> List[Dict]:
        """
        Council prioritizes targets for scanning
        """
        topic = f"""Prioritize these targets for security testing:
        {json.dumps(targets, indent=2)}
        
        Consider: attack surface, potential impact, likelihood of vulnerabilities"""
        
        decision = await self.convene(topic, {'targets': targets})
        
        # Parse decision to extract prioritized list
        # In production, this would be more sophisticated
        prioritized = []
        for i, target in enumerate(targets):
            prioritized.append({
                'target': target,
                'priority': i + 1,
                'reasoning': decision['consensus'].get('sentiment', 'unknown')
            })
        
        return prioritized
    
    async def generate_exploit_strategy(self, vulnerability: Dict) -> Dict:
        """
        Council collaborates to generate exploitation strategy
        """
        topic = f"""Develop an exploitation strategy for:
        {json.dumps(vulnerability, indent=2)}
        
        Provide specific techniques, payloads, and validation methods."""
        
        decision = await self.convene(topic, vulnerability)
        
        # Extract strategy from deliberations
        strategies = []
        for delib in decision['deliberations']:
            if delib['role'] in ['attacker', 'specialist', 'innovator']:
                strategies.append({
                    'source': delib['member'],
                    'strategy': delib['assessment'],
                    'confidence': delib['confidence']
                })
        
        return {
            'vulnerability': vulnerability,
            'strategies': strategies,
            'recommended': strategies[0] if strategies else None,
            'consensus': decision['consensus']
        }
    
    def get_performance_report(self) -> Dict:
        """Get performance report for the council"""
        report = {
            'total_decisions': len(self.decisions),
            'members': []
        }
        
        for member in self.members:
            accuracy = member.correct_votes / member.votes_cast if member.votes_cast > 0 else 0
            report['members'].append({
                'name': member.name,
                'role': member.role.value,
                'model': member.model_name,
                'votes_cast': member.votes_cast,
                'accuracy': accuracy,
                'influence_score': member.influence_score
            })
        
        return report