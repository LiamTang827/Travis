# ============================================================
# STEP 1: 在 VSCode 终端运行以下命令配置环境
# ============================================================

# 1. 创建 conda 环境
conda create -n lucidaml python=3.11 -y
conda activate lucidaml

# 2. 安装依赖
pip install requests flask flask-cors

# 3. 进入项目目录
cd ~/Desktop/stbc/compliance_engine

# 4. 运行批量分析
python batch_analyze.py --hops 3
