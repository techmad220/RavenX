"""
Council Agent - Specialized agent for participating in the AI Council
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
import json
from datetime import datetime

from .base import BaseAgent
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class CouncilAgent(BaseAgent):
    """
    Specialized agent that participates in council deliberations
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.council_role = config.get('role', 'member')
        self.specialization = config.get('specialization', [])
        
        # Track deliberation history for context
        self.deliberation_history = []
        self.max_history = 20
        
        logger.debug(f"CouncilAgent {self.name} initialized as {self.council_role}")
    
    def _get_system_prompt(self) -> str:
        """Get role-specific system prompt"""
        base_prompt = self.config.get('system_prompt', '')
        
        if base_prompt:
            return base_prompt
        
        # Default prompt if none provided
        return f"""You are {self.name}, a {self.council_role} on the AI Security Council.
        Your role is to provide expert analysis and recommendations for security vulnerabilities.
        
        Guidelines:
        1. Be specific and technical in your assessments
        2. Provide evidence-based reasoning
        3. Consider both offensive and defensive perspectives
        4. Express confidence levels clearly
        5. Highlight any uncertainties or edge cases
        
        Specializations: {', '.join(self.specialization) if self.specialization else 'General security'}
        
        When evaluating vulnerabilities:
        - Assess exploitability and impact
        - Consider false positive indicators
        - Recommend specific validation steps
        - Suggest remediation approaches
        """
    
    async def analyze(self, target: Any) -> Dict:
        """
        Analyze a target from the council member's perspective
        """
        analysis_prompt = f"""Analyze this target from your perspective as {self.council_role}:
        Target: {target}
        
        Provide:
        1. Initial assessment
        2. Potential vulnerabilities
        3. Risk factors
        4. Recommended approach
        5. Confidence level (0-1)
        """
        
        response = await self.think(analysis_prompt, {'target': target})
        
        return self._parse_analysis(response)
    
    def _parse_analysis(self, response: str) -> Dict:
        """Parse analysis response into structured format"""
        analysis = {
            'assessment': '',
            'vulnerabilities': [],
            'risk_factors': [],
            'approach': '',
            'confidence': 0.5
        }
        
        # Simple parsing - in production use NLP
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if 'assessment' in line.lower():
                current_section = 'assessment'
            elif 'vulnerabilit' in line.lower():
                current_section = 'vulnerabilities'
            elif 'risk' in line.lower():
                current_section = 'risk_factors'
            elif 'approach' in line.lower():
                current_section = 'approach'
            elif 'confidence' in line.lower():
                # Extract confidence value
                import re
                numbers = re.findall(r'[\d.]+', line)
                if numbers:
                    analysis['confidence'] = float(numbers[0])
            elif current_section:
                if current_section in ['vulnerabilities', 'risk_factors']:
                    if line.startswith('-') or line.startswith('*'):
                        analysis[current_section].append(line[1:].strip())
                else:
                    analysis[current_section] += line + ' '
        
        return analysis
    
    async def execute(self, task: Dict) -> Any:
        """
        Execute a council-specific task
        """
        task_type = task.get('type')
        
        if task_type == 'deliberate':
            return await self.deliberate(task.get('topic'), task.get('context'))
        elif task_type == 'vote':
            return await self.vote(task.get('proposal'), task.get('options'))
        elif task_type == 'review':
            return await self.review(task.get('findings'))
        elif task_type == 'strategize':
            return await self.strategize(task.get('objective'), task.get('constraints'))
        else:
            logger.warning(f"Unknown council task type: {task_type}")
            return None
    
    async def deliberate(self, topic: str, context: Dict = None) -> str:
        """
        Deliberate on a specific topic
        """
        # Add historical context
        historical_context = self._get_relevant_history(topic)
        
        deliberation_prompt = f"""As {self.council_role}, deliberate on:
        {topic}
        
        Context: {json.dumps(context, indent=2) if context else 'None'}
        
        Previous relevant deliberations: {historical_context}
        
        Provide your expert assessment considering:
        1. Technical feasibility
        2. Security implications
        3. Risk vs reward
        4. Potential false positives
        5. Your confidence level
        
        Be specific and cite evidence where possible.
        """
        
        response = await self.think(deliberation_prompt, context)
        
        # Store in history
        self._add_to_history(topic, response)
        
        return response
    
    async def vote(self, proposal: str, options: List[str]) -> Dict:
        """
        Vote on a proposal with reasoning
        """
        vote_prompt = f"""Vote on this proposal:
        {proposal}
        
        Options: {', '.join(options)}
        
        Provide:
        1. Your vote
        2. Detailed reasoning
        3. Confidence level (0-1)
        4. Any concerns or caveats
        """
        
        response = await self.think(vote_prompt)
        
        # Parse vote from response
        vote_result = self._parse_vote(response, options)
        
        return vote_result
    
    def _parse_vote(self, response: str, options: List[str]) -> Dict:
        """Parse voting response"""
        vote = {
            'choice': None,
            'reasoning': response,
            'confidence': 0.5,
            'concerns': []
        }
        
        # Find which option was chosen
        response_lower = response.lower()
        for option in options:
            if option.lower() in response_lower:
                vote['choice'] = option
                break
        
        # Extract confidence if mentioned
        import re
        confidence_match = re.search(r'confidence[:\s]+([0-9.]+)', response_lower)
        if confidence_match:
            vote['confidence'] = float(confidence_match.group(1))
        
        return vote
    
    async def review(self, findings: List[Dict]) -> Dict:
        """
        Review and validate findings
        """
        review_prompt = f"""Review these security findings:
        {json.dumps(findings, indent=2)}
        
        For each finding, assess:
        1. Validity (is it real?)
        2. Severity (critical/high/medium/low)
        3. Exploitability (easy/moderate/difficult)
        4. Impact (what could an attacker achieve?)
        5. Confidence in assessment
        
        Flag any false positives or uncertainties.
        """
        
        response = await self.think(review_prompt, {'findings': findings})
        
        return self._parse_review(response)
    
    def _parse_review(self, response: str) -> Dict:
        """Parse review response"""
        return {
            'review': response,
            'timestamp': datetime.now().isoformat(),
            'reviewer': self.name,
            'role': self.council_role
        }
    
    async def strategize(self, objective: str, constraints: Dict = None) -> Dict:
        """
        Develop strategy for achieving objective
        """
        strategy_prompt = f"""Develop a strategy for:
        {objective}
        
        Constraints: {json.dumps(constraints, indent=2) if constraints else 'None'}
        
        Provide:
        1. Overall approach
        2. Step-by-step plan
        3. Required resources
        4. Risk assessment
        5. Success metrics
        6. Contingency plans
        """
        
        response = await self.think(strategy_prompt, {'constraints': constraints})
        
        return {
            'objective': objective,
            'strategy': response,
            'strategist': self.name,
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_relevant_history(self, topic: str, max_items: int = 3) -> str:
        """Get relevant historical deliberations"""
        if not self.deliberation_history:
            return "No previous deliberations"
        
        # Simple relevance: most recent
        # In production, use semantic similarity
        relevant = self.deliberation_history[-max_items:]
        
        history_str = "\n".join([
            f"- {item['topic'][:50]}: {item['response'][:100]}..."
            for item in relevant
        ])
        
        return history_str
    
    def _add_to_history(self, topic: str, response: str):
        """Add deliberation to history"""
        self.deliberation_history.append({
            'timestamp': datetime.now().isoformat(),
            'topic': topic,
            'response': response
        })
        
        # Trim history if too large
        if len(self.deliberation_history) > self.max_history:
            self.deliberation_history = self.deliberation_history[-self.max_history:]
    
    async def collaborate(self, other_agent: 'CouncilAgent', task: str) -> Dict:
        """
        Collaborate with another council member
        """
        collab_prompt = f"""Collaborate with {other_agent.name} ({other_agent.council_role}) on:
        {task}
        
        Your role: {self.council_role}
        Their role: {other_agent.council_role}
        
        Provide your perspective and suggestions for collaboration.
        """
        
        my_perspective = await self.think(collab_prompt)
        
        # Get other agent's perspective
        their_perspective = await other_agent.think(
            f"Collaborate with {self.name} ({self.council_role}) on: {task}"
        )
        
        return {
            'task': task,
            'collaboration': {
                self.name: my_perspective,
                other_agent.name: their_perspective
            },
            'timestamp': datetime.now().isoformat()
        }