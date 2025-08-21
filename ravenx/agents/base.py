"""
Base AI Agent class for autonomous security research
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import openai
import anthropic
from datetime import datetime
import json
import hashlib

from ..utils.logger import setup_logger
from ..utils.rate_limiter import RateLimiter

logger = setup_logger(__name__)

class BaseAgent(ABC):
    """
    Abstract base class for all AI agents
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.session_id = None
        self.rate_limiter = RateLimiter(config.get('rate_limit', 10))
        
        # Initialize AI clients
        self._init_ai_clients()
        
        # Agent memory for context retention
        self.memory = []
        self.max_memory = config.get('max_memory', 100)
        
        # Performance metrics
        self.metrics = {
            'requests': 0,
            'successes': 0,
            'failures': 0,
            'avg_response_time': 0
        }
        
        logger.debug(f"{self.name} initialized")
    
    def _init_ai_clients(self):
        """Initialize AI model clients"""
        self.ai_provider = self.config.get('ai_provider', 'openai')
        
        if self.ai_provider == 'openai':
            openai.api_key = self.config.get('openai_api_key')
            self.model = self.config.get('openai_model', 'gpt-4-turbo-preview')
        elif self.ai_provider == 'anthropic':
            self.anthropic_client = anthropic.Anthropic(
                api_key=self.config.get('anthropic_api_key')
            )
            self.model = self.config.get('anthropic_model', 'claude-3-opus-20240229')
        else:
            # Default to a local model or mock
            self.model = 'local'
    
    async def think(self, prompt: str, context: Dict = None) -> str:
        """
        Agent's thinking process using AI
        """
        await self.rate_limiter.acquire()
        
        start_time = datetime.now()
        self.metrics['requests'] += 1
        
        try:
            # Add context to prompt
            full_prompt = self._build_prompt(prompt, context)
            
            # Get AI response
            if self.ai_provider == 'openai':
                response = await self._openai_think(full_prompt)
            elif self.ai_provider == 'anthropic':
                response = await self._anthropic_think(full_prompt)
            else:
                response = await self._local_think(full_prompt)
            
            # Update metrics
            self.metrics['successes'] += 1
            response_time = (datetime.now() - start_time).total_seconds()
            self._update_avg_response_time(response_time)
            
            # Store in memory
            self._add_to_memory(prompt, response)
            
            return response
            
        except Exception as e:
            self.metrics['failures'] += 1
            logger.error(f"{self.name} thinking error: {e}")
            return ""
    
    async def _openai_think(self, prompt: str) -> str:
        """OpenAI API call"""
        try:
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return ""
    
    async def _anthropic_think(self, prompt: str) -> str:
        """Anthropic API call"""
        try:
            response = await asyncio.to_thread(
                self.anthropic_client.messages.create,
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                system=self._get_system_prompt(),
                max_tokens=2000
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return ""
    
    async def _local_think(self, prompt: str) -> str:
        """Local model or mock response"""
        # This would integrate with a local model
        # For now, return a mock response
        await asyncio.sleep(0.1)  # Simulate processing time
        return f"Mock response for: {prompt[:50]}..."
    
    def _build_prompt(self, prompt: str, context: Dict = None) -> str:
        """Build full prompt with context"""
        full_prompt = prompt
        
        if context:
            context_str = json.dumps(context, indent=2)
            full_prompt = f"Context:\n{context_str}\n\nTask:\n{prompt}"
        
        # Add relevant memory
        if self.memory:
            memory_context = self._get_relevant_memory(prompt)
            if memory_context:
                full_prompt = f"Previous knowledge:\n{memory_context}\n\n{full_prompt}"
        
        return full_prompt
    
    def _get_relevant_memory(self, prompt: str, max_items: int = 5) -> str:
        """Get relevant items from memory"""
        # Simple relevance: most recent items
        # In production, use semantic similarity
        relevant = self.memory[-max_items:] if self.memory else []
        
        if relevant:
            memory_str = "\n".join([
                f"- {item['prompt'][:50]}: {item['response'][:100]}"
                for item in relevant
            ])
            return memory_str
        
        return ""
    
    def _add_to_memory(self, prompt: str, response: str):
        """Add interaction to memory"""
        self.memory.append({
            'timestamp': datetime.now().isoformat(),
            'prompt': prompt,
            'response': response,
            'hash': hashlib.md5(f"{prompt}{response}".encode()).hexdigest()
        })
        
        # Trim memory if too large
        if len(self.memory) > self.max_memory:
            self.memory = self.memory[-self.max_memory:]
    
    def _update_avg_response_time(self, new_time: float):
        """Update average response time"""
        current_avg = self.metrics['avg_response_time']
        total_requests = self.metrics['successes']
        
        if total_requests == 1:
            self.metrics['avg_response_time'] = new_time
        else:
            self.metrics['avg_response_time'] = (
                (current_avg * (total_requests - 1) + new_time) / total_requests
            )
    
    @abstractmethod
    def _get_system_prompt(self) -> str:
        """Get system prompt for the agent"""
        pass
    
    @abstractmethod
    async def analyze(self, target: Any) -> Dict:
        """Analyze a target"""
        pass
    
    @abstractmethod
    async def execute(self, task: Dict) -> Any:
        """Execute a specific task"""
        pass
    
    def get_metrics(self) -> Dict:
        """Get agent metrics"""
        return {
            'agent': self.name,
            'metrics': self.metrics,
            'memory_size': len(self.memory)
        }
    
    def reset(self):
        """Reset agent state"""
        self.memory = []
        self.metrics = {
            'requests': 0,
            'successes': 0,
            'failures': 0,
            'avg_response_time': 0
        }