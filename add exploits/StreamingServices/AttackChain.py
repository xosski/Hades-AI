import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch

# Extended attack chain stages
stages = [
    "Initial Injection (DNS Poisoning / XSS)",
    "Stream Manipulation",
    "CSS Overlay Abuse (Facebook Player)",
    "Service Worker Persistence",
    "Social Engineering Seed"
]

# Create diagram
fig, ax = plt.subplots(figsize=(10, 7))
ax.set_xlim(0, 10)
ax.set_ylim(0, len(stages) * 2)
ax.axis('off')

# Draw stages
for i, stage in enumerate(stages):
    y = len(stages)*2 - (i * 2) - 1
    ax.text(
        5, y, stage,
        ha='center', va='center',
        fontsize=12, fontweight='bold',
        color='white',
        bbox=dict(
            facecolor='black', edgecolor='white',
            boxstyle='round,pad=0.4', alpha=0.9, lw=1.5
        )
    )
    # Draw arrow to next stage
    if i < len(stages) - 1:
        arrow = FancyArrowPatch(
            (5, y - 0.8), (5, y - 1.2),
            arrowstyle='->', color='white', linewidth=2
        )
        ax.add_patch(arrow)

# Title
plt.title(
    "Extended Attack Chain Diagram",
    fontsize=14, fontweight='bold',
    color='white', backgroundcolor='black', pad=15
)

# Background
ax.set_facecolor('black')
fig.patch.set_facecolor('black')

plt.tight_layout()
plt.show()