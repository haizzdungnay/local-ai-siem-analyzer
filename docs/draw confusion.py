import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from matplotlib.colors import LinearSegmentedColormap
import numpy as np

plt.rcParams['font.family'] = 'DejaVu Sans'

LABELS = ['low', 'medium', 'high', 'không\nhợp lệ']
NCOL = 4
# rows = ground truth (mức chuẩn), cols = predicted [low, medium, high, không hợp lệ]
MAT = np.array([
    [10, 2, 0, 1],
    [4, 9, 0, 0],
    [1, 3, 3, 0],
])
ROW_TOTAL = MAT.sum(axis=1)  # 13,13,7

fig, ax = plt.subplots(figsize=(8.6, 6.6))

# custom colormap: light -> deep teal
cmap = LinearSegmentedColormap.from_list('teal', ['#f3f7f6', '#1f6f5c'])

# normalize by row (recall-style) for coloring, so each row's proportions are comparable
norm_mat = MAT / ROW_TOTAL[:, None]

im = ax.imshow(norm_mat, cmap=cmap, vmin=0, vmax=1, aspect='equal')

ax.set_xticks(range(NCOL))
ax.set_yticks(range(3))
ax.set_xticklabels(LABELS, fontsize=14, fontweight='bold')
ax.set_yticklabels(['low', 'medium', 'high'], fontsize=15, fontweight='bold')
ax.set_xlabel('Mức do mô hình dự đoán', fontsize=13.5, labelpad=12)
ax.set_ylabel('Mức chuẩn (ground truth)', fontsize=13.5, labelpad=12)
ax.xaxis.set_label_position('top')
ax.xaxis.tick_top()

# gridlines between cells
ax.set_xticks(np.arange(-.5, NCOL, 1), minor=True)
ax.set_yticks(np.arange(-.5, 3, 1), minor=True)
ax.grid(which='minor', color='white', linewidth=3)
ax.tick_params(which='minor', size=0)
ax.tick_params(which='major', length=0)

for i in range(3):
    for j in range(NCOL):
        val = MAT[i, j]
        pct = val / ROW_TOTAL[i] * 100
        color = 'white' if norm_mat[i, j] > 0.55 else '#1a1a1a'
        is_diag = (i == j and j < 3)
        weight = 'bold' if is_diag else 'normal'
        fs = 22 if is_diag else 17
        ax.text(j, i - 0.10, f'{val}', ha='center', va='center',
                fontsize=fs, fontweight=weight, color=color)
        ax.text(j, i + 0.22, f'{pct:.0f}%', ha='center', va='center',
                fontsize=11, color=color, alpha=0.9)
        # highlight the dangerous under-severity cells for 'high' row (predicted low/medium)
        if i == 2 and j < 2:
            ax.add_patch(plt.Rectangle((j-0.5, i-0.5), 1, 1, fill=False,
                                         edgecolor='#c1440e', linewidth=3.5, zorder=10))

ax.set_title('Ma trận nhầm lẫn — mức nghiêm trọng\n(cấu hình A: qwen2.5:7b có RAG)',
              fontsize=14.5, pad=50, color='#222')

# row totals as small text on the right
for i in range(3):
    ax.text(NCOL - 0.5 + 0.35, i, f'n={ROW_TOTAL[i]}', ha='left', va='center', fontsize=11, color='#555')

plt.tight_layout()

# annotate the highlighted danger zone below the whole figure, using figure coords
fig.subplots_adjust(bottom=0.18)
fig.text(0.5, 0.035,
         '⚠ 4/7 case mức "high" bị đánh giá thấp hơn (ô viền cam ở hàng dưới) — vùng nguy hiểm nhất',
         fontsize=12, color='#c1440e', ha='center', fontweight='bold')
plt.savefig('C:\\Users\\Tplab\\local-ai-siem-analyzer\\docs\\confusion_matrix_severity.png', dpi=220,
            bbox_inches='tight', facecolor='white')
print('done')
