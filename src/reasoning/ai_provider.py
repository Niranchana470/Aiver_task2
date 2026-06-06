"""
AI Provider Interface and Implementations
Supports multiple AI providers for reasoning and decision-making
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import os
import json


@dataclass
class AIResponse:
    """Structured response from AI provider"""
    content: str
    reasoning: Optional[str] = None
    confidence: float = 0.0
    metadata: Optional[Dict[str, Any]] = None
    tokens_used: Optional[int] = None
    model_used: Optional[str] = None


class AIProvider(ABC):
    """Abstract base class for AI providers"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.model = config.get("model", "gpt-4")
        self.api_key = config.get("api_key")
        self.temperature = config.get("temperature", 0.0)  # Low temp for consistent reasoning
        
    @abstractmethod
    def complete(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Complete a prompt with the AI model"""
        pass
    
    @abstractmethod
    def complete_with_reasoning(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Complete a prompt and return both response and reasoning"""
        pass
    
    def _validate_api_key(self) -> bool:
        """Validate that API key is present"""
        if not self.api_key:
            self.logger.error("API key not configured")
            return False
        return True


class OpenAIProvider(AIProvider):
    """OpenAI GPT-4 provider"""
    
    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        try:
            import openai
            self.openai = openai
            if self.api_key:
                self.openai.api_key = self.api_key
            else:
                self.openai.api_key = os.getenv("OPENAI_API_KEY")
            self.logger.info(f"Initialized OpenAI provider with model: {self.model}")
        except ImportError:
            self.logger.error("OpenAI package not installed. Install with: pip install openai>=1.0.0")
            raise
    
    def complete(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Complete a prompt using OpenAI"""
        if not self._validate_api_key():
            return AIResponse(content="", confidence=0.0)
        
        try:
            messages = [{"role": "system", "content": "You are a security analysis assistant."}]
            
            if context:
                messages.append({
                    "role": "system", 
                    "content": f"Context: {json.dumps(context, indent=2)}"
                })
            
            messages.append({"role": "user", "content": prompt})
            
            response = self.openai.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=2000
            )
            
            content = response.choices[0].message.content
            tokens_used = response.usage.total_tokens if response.usage else 0
            
            return AIResponse(
                content=content,
                tokens_used=tokens_used,
                model_used=self.model,
                metadata={"provider": "openai"}
            )
            
        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            return AIResponse(content="", confidence=0.0)
    
    def complete_with_reasoning(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Complete with explicit reasoning step"""
        reasoning_prompt = f"""
Think step-by-step about this security analysis:

{prompt}

Provide your response in this format:
REASONING: [Your step-by-step reasoning]
ANSWER: [Your final answer]
CONFIDENCE: [0-100]
"""
        
        response = self.complete(reasoning_prompt, context)
        
        # Parse response to extract reasoning, answer, confidence
        reasoning = ""
        answer = response.content
        confidence = 0.7
        
        if "REASONING:" in response.content:
            parts = response.content.split("REASONING:")
            if "ANSWER:" in parts[1]:
                reasoning_part, answer_part = parts[1].split("ANSWER:")
                reasoning = reasoning_part.strip()
                answer = answer_part.strip()
                
                if "CONFIDENCE:" in answer_part:
                    answer_final, confidence_part = answer_part.split("CONFIDENCE:")
                    answer = answer_final.strip()
                    try:
                        confidence = float(confidence_part.strip()) / 100.0
                    except:
                        confidence = 0.7
        
        return AIResponse(
            content=answer,
            reasoning=reasoning,
            confidence=confidence,
            tokens_used=response.tokens_used,
            model_used=response.model_used,
            metadata=response.metadata
        )


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider"""
    
    def __init__(self, config: Dict[str, Any], logger):
        super().__init__(config, logger)
        try:
            import anthropic
            self.anthropic = anthropic
            if self.api_key:
                self.client = anthropic.Anthropic(api_key=self.api_key)
            else:
                api_key = os.getenv("ANTHROPIC_API_KEY")
                self.client = anthropic.Anthropic(api_key=api_key)
            self.logger.info(f"Initialized Anthropic provider with model: {self.model}")
        except ImportError:
            self.logger.error("Anthropic package not installed. Install with: pip install anthropic")
            raise
    
    def complete(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Complete a prompt using Anthropic Claude"""
        if not self._validate_api_key():
            return AIResponse(content="", confidence=0.0)
        
        try:
            system_prompt = "You are a security analysis assistant."
            if context:
                system_prompt += f"\n\nContext: {json.dumps(context, indent=2)}"
            
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature
            )
            
            content = message.content[0].text
            tokens_used = message.usage.input_tokens + message.usage.output_tokens
            
            return AIResponse(
                content=content,
                tokens_used=tokens_used,
                model_used=self.model,
                metadata={"provider": "anthropic"}
            )
            
        except Exception as e:
            self.logger.error(f"Anthropic API error: {e}")
            return AIResponse(content="", confidence=0.0)
    
    def complete_with_reasoning(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Complete with explicit reasoning (Claude does this naturally)"""
        thinking_prompt = f"""
Think step-by-step about this security analysis:

{prompt}

Provide your reasoning and final answer clearly.
"""
        
        response = self.complete(thinking_prompt, context)
        
        # Claude naturally includes reasoning, so we extract it if present
        reasoning = ""
        answer = response.content
        
        # Simple heuristic: if there's clear structure, extract reasoning
        if "My reasoning:" in response.content or "Analysis:" in response.content:
            lines = response.content.split('\n')
            reasoning_lines = []
            answer_lines = []
            in_reasoning = False
            in_answer = False
            
            for line in lines:
                if 'reasoning:' in line.lower() or 'analysis:' in line.lower():
                    in_reasoning = True
                    in_answer = False
                    reasoning_lines.append(line)
                elif 'answer:' in line.lower() or 'conclusion:' in line.lower():
                    in_answer = True
                    in_reasoning = False
                    answer_lines.append(line)
                elif in_reasoning:
                    reasoning_lines.append(line)
                elif in_answer:
                    answer_lines.append(line)
            
            reasoning = '\n'.join(reasoning_lines).strip()
            answer = '\n'.join(answer_lines).strip()
        
        return AIResponse(
            content=answer or response.content,
            reasoning=reasoning,
            confidence=0.8,  # Claude typically has good reasoning
            tokens_used=response.tokens_used,
            model_used=response.model_used,
            metadata=response.metadata
        )


class MockProvider(AIProvider):
    """Mock provider for testing without API calls"""
    
    def complete(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Mock completion for testing"""
        self.logger.warning("Using mock AI provider - responses will be generic")
        
        return AIResponse(
            content="[MOCK RESPONSE] This is a simulated AI response for testing purposes.",
            reasoning="[MOCK REASONING] This is simulated reasoning.",
            confidence=0.5,
            tokens_used=100,
            model_used="mock-model",
            metadata={"provider": "mock"}
        )
    
    def complete_with_reasoning(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> AIResponse:
        """Mock completion with reasoning"""
        return self.complete(prompt, context)


def create_ai_provider(config: Dict[str, Any], logger) -> AIProvider:
    """Factory function to create AI provider based on configuration"""
    provider_type = config.get("provider", "openai").lower()
    
    provider_map = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "claude": AnthropicProvider,
        "mock": MockProvider
    }
    
    provider_class = provider_map.get(provider_type)
    if not provider_class:
        raise ValueError(f"Unknown AI provider: {provider_type}. Available: {list(provider_map.keys())}")
    
    return provider_class(config, logger)
