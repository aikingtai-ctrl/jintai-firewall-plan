#!/usr/bin/env bash
# ============================================================================
# 金泰 AI 平台 L1 本地安全护栏模型部署脚本 (A 机 172.16.0.10 专用)
# ============================================================================
# 用途：在 A 机 (8×H100) 上启动阿里通义开源 Qwen3Guard-Gen-4B 语义护栏服务 (:8000)
# 优势：仅占单张 H100 约 8% 显存 (~6.5GB)，延迟 < 35ms，0 云端 API 费用，拦截 30% 隐晦越狱与内部草稿
# ============================================================================

set -euo pipefail

MODEL_ID="${JINTAI_L1_GUARD_MODEL:-Qwen/Qwen3Guard-Gen-4B}"
PORT="${JINTAI_L1_GUARD_PORT:-8000}"
GPU_DEVICE="${CUDA_VISIBLE_DEVICES:-0}"

echo "============================================================"
echo "[Jintai L1 Guard] 正在 A 机 (172.16.0.10) 启动 Qwen3Guard-4B 护栏服务"
echo "  模型: ${MODEL_ID}"
echo "  端口: :${PORT} (OpenAI 兼容接口 /v1/chat/completions)"
echo "  显卡: GPU #${GPU_DEVICE} (限制显存占用 0.12，不影响 8188-8194 ComfyUI 出片)"
echo "============================================================"

export CUDA_VISIBLE_DEVICES="${GPU_DEVICE}"
export HF_ENDPOINT="${HF_ENDPOINT:-https://hf-mirror.com}"

exec python3 -m vllm.entrypoints.openai.api_server \
  --model "${MODEL_ID}" \
  --served-model-name "Qwen/Qwen3Guard-Gen-4B" \
  --host 0.0.0.0 \
  --port "${PORT}" \
  --dtype bfloat16 \
  --gpu-memory-utilization 0.12 \
  --max-model-len 4096 \
  --disable-log-requests
