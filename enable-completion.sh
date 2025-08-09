#!/bin/bash
# Quick script to enable Authly tab completion in current shell

echo "🔧 Enabling Authly tab completion..."

# Generate completion script
python -m authly completion bash > /tmp/authly-completion.bash

# Source it
source /tmp/authly-completion.bash

echo "✅ Tab completion enabled for this session!"
echo ""
echo "Try it now:"
echo "  python -m authly <press TAB>"
echo "  python -m authly admin <press TAB>"
echo "  python -m authly admin auth <press TAB>"
echo ""
echo "To make it permanent, add this to your ~/.bashrc:"
echo "  python -m authly completion bash > ~/.bash_completion.d/authly"
echo "  source ~/.bash_completion.d/authly"