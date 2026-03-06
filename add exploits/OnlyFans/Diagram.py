import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Create the diagram
fig, ax = plt.subplots(figsize=(10, 6))
ax.set_xlim(0, 10)
ax.set_ylim(0, 6)
ax.axis('off')

# Define nodes and positions
nodes = {
    "Locked Post": (1, 3),
    "Public CDN Link": (4, 3),
    "Unauthorized Access": (7, 3),
    "Possible Enumeration": (9, 5),
    "Revenue Loss / Privacy Breach": (9, 1)
}

# Draw nodes
for label, (x, y) in nodes.items():
    ax.add_patch(mpatches.FancyBboxPatch(
        (x-0.9, y-0.4), 1.8, 0.8,
        boxstyle="round,pad=0.1", fc="lightblue", ec="black"
    ))
    ax.text(x, y, label, ha='center', va='center', fontsize=9, wrap=True)

# Draw arrows
arrows = [
    ("Locked Post", "Public CDN Link"),
    ("Public CDN Link", "Unauthorized Access"),
    ("Unauthorized Access", "Possible Enumeration"),
    ("Unauthorized Access", "Revenue Loss / Privacy Breach")
]

for start, end in arrows:
    sx, sy = nodes[start]
    ex, ey = nodes[end]
    ax.annotate(
        "", xy=(ex, ey), xytext=(sx, sy),
        arrowprops=dict(arrowstyle="->", lw=1.2)
    )

# Title
ax.set_title("Threat Flow Diagram: OnlyFans Media Access Control Flaw", fontsize=14, fontweight='bold')

# Save or show
plt.tight_layout()
plt.show()