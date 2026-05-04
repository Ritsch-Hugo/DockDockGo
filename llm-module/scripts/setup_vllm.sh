#!/usr/bin/env bash
# setup_vllm.sh — Crée le virtualenv Python et installe vLLM dans llm-module/.venv
# Usage : bash llm-module/scripts/setup_vllm.sh
# À lancer une seule fois après avoir cloné le repo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/../.venv"

echo "=== Vérification Python ==="
if ! command -v python3 &>/dev/null; then
    echo "ERREUR : python3 introuvable. Installe Python 3.10+ avant de continuer."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python détecté : $PYTHON_VERSION"

echo ""
echo "=== Création du virtualenv dans $VENV_DIR ==="
python3 -m venv "$VENV_DIR"
echo "Virtualenv créé."

echo ""
echo "=== Installation de vLLM (peut prendre 5-15 min selon ta connexion) ==="
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install vllm

echo ""
echo "=== Vérification CUDA ==="
"$VENV_DIR/bin/python" -c "
import torch
cuda_ok = torch.cuda.is_available()
print(f'CUDA disponible : {cuda_ok}')
if cuda_ok:
    print(f'  GPU : {torch.cuda.get_device_name(0)}')
    vram = torch.cuda.get_device_properties(0).total_memory / 1024**3
    print(f'  VRAM : {vram:.1f} GB')
    print(f'  CUDA version : {torch.version.cuda}')
else:
    print('ATTENTION : CUDA non détecté. vLLM tournera sur CPU (très lent).')
"

echo ""
echo "=== Installation terminée ==="
echo ""
echo "Pour lancer vLLM :"
echo "  source llm-module/.venv/bin/activate"
echo "  vllm serve cyankiwi/Qwen3.5-9B-AWQ-4bit \\"
echo "    --enable-auto-tool-choice \\"
echo "    --tool-call-parser qwen3_coder \\"
echo "    --language-model-only \\"
echo "    --max-model-len 8192 \\"
echo "    --port 8000"
