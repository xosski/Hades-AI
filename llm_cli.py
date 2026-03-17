"""
LLM CLI - Command-line interface for Hades AI conversations
Simple, fast, and efficient terminal-based chat
"""

import sys
import os
import json
import argparse
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from llm_conversation_core import ConversationManager, LLMProvider

logger = logging.getLogger("LLMCli")

# Color codes for terminal
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Background
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


class HadesAICLI:
    """Command-line interface for Hades AI"""
    
    def __init__(self, db_path: str = "conversations.db"):
        self.manager = ConversationManager(db_path)
        self.current_conv = None
    
    def print_header(self):
        """Print fancy header"""
        header = f"""
{Colors.RED}{Colors.BOLD}
╔═══════════════════════════════════════════╗
║       {Colors.MAGENTA}🔥 HADES AI CONVERSATION CLI 🔥{Colors.RED}      ║
║     Multi-LLM Powered Chat Interface      ║
╚═══════════════════════════════════════════╝
{Colors.RESET}
Type {Colors.CYAN}'help'{Colors.RESET} for commands, {Colors.CYAN}'quit'{Colors.RESET} to exit
{Colors.DIM}Available providers: {', '.join(self.manager.get_available_providers())}{Colors.RESET}
"""
        print(header)
    
    def print_status(self):
        """Print current conversation status"""
        if self.current_conv:
            print(f"\n{Colors.CYAN}Active Conversation:{Colors.RESET}")
            print(f"  Title: {Colors.BOLD}{self.current_conv.title}{Colors.RESET}")
            print(f"  Provider: {Colors.GREEN}{self.current_conv.provider}{Colors.RESET}")
            print(f"  Model: {Colors.GREEN}{self.current_conv.model}{Colors.RESET}")
            print(f"  Messages: {Colors.YELLOW}{len(self.current_conv.messages)}{Colors.RESET}")
            print()
    
    def print_help(self):
        """Print help message"""
        help_text = f"""
{Colors.BOLD}Available Commands:{Colors.RESET}

{Colors.CYAN}Chat Commands:{Colors.RESET}
  {Colors.GREEN}new{Colors.RESET} [title]              Create new conversation
  {Colors.GREEN}list{Colors.RESET}                    List all conversations
  {Colors.GREEN}load{Colors.RESET} <conv_id>         Load conversation
  {Colors.GREEN}clear{Colors.RESET}                  Clear current conversation
  {Colors.GREEN}status{Colors.RESET}                 Show current status
  {Colors.GREEN}save{Colors.RESET}                   Save conversation to file
  {Colors.GREEN}export{Colors.RESET}                 Export as JSON

{Colors.CYAN}Settings Commands:{Colors.RESET}
  {Colors.GREEN}provider{Colors.RESET} <name>        Switch provider (openai, mistral, ollama, azure, fallback)
  {Colors.GREEN}model{Colors.RESET} <name>           Switch model
  {Colors.GREEN}temp{Colors.RESET} <0.0-1.0>        Set temperature
  {Colors.GREEN}tokens{Colors.RESET} <number>       Set max tokens
  {Colors.GREEN}system{Colors.RESET} <prompt>       Set system prompt

{Colors.CYAN}History & Management:{Colors.RESET}
  {Colors.GREEN}history{Colors.RESET}               Show message history
  {Colors.GREEN}delete{Colors.RESET} <conv_id>      Delete conversation
  {Colors.GREEN}providers{Colors.RESET}             List available providers

{Colors.CYAN}General:{Colors.RESET}
  {Colors.GREEN}help{Colors.RESET}                  Show this help
  {Colors.GREEN}quit/exit{Colors.RESET}             Exit program

{Colors.YELLOW}Type your message directly to chat{Colors.RESET}
"""
        print(help_text)
    
    def create_new_conversation(self, title: Optional[str] = None):
        """Create new conversation"""
        if not title:
            title = input(f"{Colors.CYAN}Conversation title: {Colors.RESET}").strip()
            if not title:
                title = f"Chat - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        provider = input(
            f"{Colors.CYAN}Provider ({', '.join(self.manager.get_available_providers())}): {Colors.RESET}"
        ).strip() or "openai"
        
        if provider not in self.manager.get_available_providers() and provider != "openai":
            print(f"{Colors.RED}Provider not available, using fallback{Colors.RESET}")
            provider = "fallback"
        
        model_map = {
            "openai": "gpt-3.5-turbo",
            "mistral": "mistral-tiny",
            "ollama": "llama2",
            "azure": "gpt-35-turbo",
            "fallback": "fallback"
        }
        model = model_map.get(provider, "gpt-3.5-turbo")
        
        self.current_conv = self.manager.create_conversation(
            title=title,
            provider=provider,
            model=model
        )
        
        print(f"{Colors.GREEN}✓ Created conversation: {self.current_conv.id}{Colors.RESET}")
        self.print_status()
    
    def list_conversations(self):
        """List all conversations"""
        convs = self.manager.list_conversations()
        
        if not convs:
            print(f"{Colors.YELLOW}No conversations found{Colors.RESET}")
            return
        
        print(f"\n{Colors.BOLD}Conversations:{Colors.RESET}\n")
        for i, conv in enumerate(convs, 1):
            marker = f"{Colors.GREEN}→{Colors.RESET}" if conv['id'] == (self.current_conv.id if self.current_conv else None) else " "
            print(f"{marker} {i:2}. {Colors.CYAN}{conv['title'][:40]}{Colors.RESET}")
            print(f"     ID: {Colors.DIM}{conv['id']}{Colors.RESET}")
            print(f"     Provider: {conv['provider']} | Updated: {conv['updated_at'][:10]}")
        print()
    
    def load_conversation(self, conv_id: str):
        """Load conversation"""
        conv = self.manager.load_conversation(conv_id)
        
        if not conv:
            print(f"{Colors.RED}✗ Conversation not found{Colors.RESET}")
            return
        
        self.current_conv = conv
        print(f"{Colors.GREEN}✓ Loaded conversation: {conv.title}{Colors.RESET}")
        self.print_status()
    
    def show_history(self):
        """Show message history"""
        if not self.current_conv:
            print(f"{Colors.RED}No active conversation{Colors.RESET}")
            return
        
        print(f"\n{Colors.BOLD}Message History:{Colors.RESET}\n")
        
        for i, msg in enumerate(self.current_conv.messages, 1):
            if msg.role == "user":
                print(f"{Colors.BLUE}[{i}] User:{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}[{i}] Assistant:{Colors.RESET}")
            
            content = msg.content[:100] + "..." if len(msg.content) > 100 else msg.content
            print(f"    {content}\n")
    
    def switch_provider(self, provider: str, model: Optional[str] = None):
        """Switch provider"""
        if not self.current_conv:
            print(f"{Colors.RED}No active conversation{Colors.RESET}")
            return
        
        if provider not in self.manager.get_available_providers():
            print(f"{Colors.RED}Provider not available: {provider}{Colors.RESET}")
            return
        
        if not model:
            model_map = {
                "openai": "gpt-3.5-turbo",
                "mistral": "mistral-tiny",
                "ollama": "llama2",
                "azure": "gpt-35-turbo",
                "fallback": "fallback"
            }
            model = model_map.get(provider, "gpt-3.5-turbo")
        
        self.manager.switch_provider(self.current_conv.id, provider, model)
        self.current_conv.provider = provider
        self.current_conv.model = model
        
        print(f"{Colors.GREEN}✓ Switched to {provider}/{model}{Colors.RESET}")
    
    def send_message(self, content: str):
        """Send message and stream response"""
        if not self.current_conv:
            print(f"{Colors.RED}No active conversation. Use 'new' to create one.{Colors.RESET}")
            return
        
        print(f"\n{Colors.BLUE}You:{Colors.RESET} {content}\n")
        
        print(f"{Colors.GREEN}Assistant:{Colors.RESET} ", end="", flush=True)
        
        try:
            full_response = ""
            for chunk in self.manager.send_message(content, self.current_conv.id, use_streaming=True):
                print(chunk, end="", flush=True)
                full_response += chunk
            
            print("\n")
        except Exception as e:
            print(f"\n{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    def save_to_file(self, filename: Optional[str] = None):
        """Save conversation to text file"""
        if not self.current_conv:
            print(f"{Colors.RED}No active conversation{Colors.RESET}")
            return
        
        if not filename:
            filename = f"{self.current_conv.title.replace(' ', '_')}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Conversation: {self.current_conv.title}\n")
                f.write(f"Created: {self.current_conv.created_at.isoformat()}\n")
                f.write(f"Provider: {self.current_conv.provider}\n")
                f.write("=" * 60 + "\n\n")
                
                for msg in self.current_conv.messages:
                    f.write(f"[{msg.role.upper()}] {msg.timestamp.strftime('%H:%M:%S')}\n")
                    f.write(msg.content + "\n\n")
            
            print(f"{Colors.GREEN}✓ Saved to {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    def export_json(self, filename: Optional[str] = None):
        """Export conversation as JSON"""
        if not self.current_conv:
            print(f"{Colors.RED}No active conversation{Colors.RESET}")
            return
        
        if not filename:
            filename = f"{self.current_conv.title.replace(' ', '_')}.json"
        
        try:
            export_data = {
                "id": self.current_conv.id,
                "title": self.current_conv.title,
                "created_at": self.current_conv.created_at.isoformat(),
                "provider": self.current_conv.provider,
                "model": self.current_conv.model,
                "messages": [msg.to_dict() for msg in self.current_conv.messages]
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"{Colors.GREEN}✓ Exported to {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    def delete_conversation(self, conv_id: str):
        """Delete conversation"""
        if not conv_id:
            conv_id = input(f"{Colors.CYAN}Conversation ID: {Colors.RESET}").strip()
        
        confirm = input(f"{Colors.YELLOW}Delete conversation? (y/n): {Colors.RESET}").strip().lower()
        
        if confirm == 'y':
            if self.manager.delete_conversation(conv_id):
                print(f"{Colors.GREEN}✓ Deleted{Colors.RESET}")
                if self.current_conv and self.current_conv.id == conv_id:
                    self.current_conv = None
            else:
                print(f"{Colors.RED}✗ Failed to delete{Colors.RESET}")
    
    def run(self):
        """Main CLI loop"""
        self.print_header()
        
        while True:
            try:
                if self.current_conv:
                    prompt = f"{Colors.MAGENTA}[{self.current_conv.provider[:3]}]{Colors.RESET} > "
                else:
                    prompt = f"{Colors.DIM}> {Colors.RESET}"
                
                user_input = input(prompt).strip()
                
                if not user_input:
                    continue
                
                # Parse commands
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else None
                
                if command in ['quit', 'exit']:
                    print(f"{Colors.CYAN}Goodbye!{Colors.RESET}")
                    break
                
                elif command == 'help':
                    self.print_help()
                
                elif command == 'new':
                    self.create_new_conversation(args)
                
                elif command == 'list':
                    self.list_conversations()
                
                elif command == 'load':
                    if not args:
                        print(f"{Colors.RED}Usage: load <conversation_id>{Colors.RESET}")
                    else:
                        self.load_conversation(args)
                
                elif command == 'clear':
                    if self.current_conv:
                        self.current_conv.messages = []
                        self.manager._save_conversation(self.current_conv)
                        print(f"{Colors.GREEN}✓ Cleared{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}No active conversation{Colors.RESET}")
                
                elif command == 'status':
                    self.print_status()
                
                elif command == 'history':
                    self.show_history()
                
                elif command == 'provider':
                    if not args:
                        print(f"{Colors.RED}Usage: provider <name> [model]{Colors.RESET}")
                    else:
                        pargs = args.split()
                        self.switch_provider(pargs[0], pargs[1] if len(pargs) > 1 else None)
                
                elif command == 'providers':
                    print(f"Available: {', '.join(self.manager.get_available_providers())}")
                
                elif command == 'save':
                    self.save_to_file(args)
                
                elif command == 'export':
                    self.export_json(args)
                
                elif command == 'delete':
                    self.delete_conversation(args)
                
                elif command == 'temp':
                    if self.current_conv and args:
                        try:
                            self.current_conv.temperature = float(args)
                            self.manager._save_conversation(self.current_conv)
                            print(f"{Colors.GREEN}✓ Temperature set to {args}{Colors.RESET}")
                        except ValueError:
                            print(f"{Colors.RED}Invalid temperature value{Colors.RESET}")
                
                elif command == 'tokens':
                    if self.current_conv and args:
                        try:
                            self.current_conv.max_tokens = int(args)
                            self.manager._save_conversation(self.current_conv)
                            print(f"{Colors.GREEN}✓ Max tokens set to {args}{Colors.RESET}")
                        except ValueError:
                            print(f"{Colors.RED}Invalid token value{Colors.RESET}")
                
                elif command == 'model':
                    if self.current_conv and args:
                        self.current_conv.model = args
                        self.manager._save_conversation(self.current_conv)
                        print(f"{Colors.GREEN}✓ Model set to {args}{Colors.RESET}")
                
                else:
                    # Treat as message
                    self.send_message(user_input)
            
            except KeyboardInterrupt:
                print(f"\n{Colors.CYAN}Goodbye!{Colors.RESET}")
                break
            except Exception as e:
                logger.error(f"Error: {str(e)}")
                print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Hades AI Conversation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python llm_cli.py                    Start interactive CLI
  python llm_cli.py --new "My Chat"   Create new conversation
  python llm_cli.py --load <id>       Load conversation
        """
    )
    
    parser.add_argument('--db', default='conversations.db', help='Database path')
    parser.add_argument('--new', help='Create new conversation with title')
    parser.add_argument('--load', help='Load conversation by ID')
    parser.add_argument('--list', action='store_true', help='List conversations')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    cli = HadesAICLI(args.db)
    
    if args.list:
        cli.list_conversations()
    elif args.load:
        cli.load_conversation(args.load)
        cli.run()
    elif args.new:
        cli.create_new_conversation(args.new)
        cli.run()
    else:
        cli.run()


if __name__ == "__main__":
    main()
