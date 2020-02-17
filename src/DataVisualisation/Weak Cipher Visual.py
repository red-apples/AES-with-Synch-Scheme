from pathlib import Path

import pandas as pd

from bokeh.models import Range1d
from bokeh.plotting import figure, show, output_file

parentDir = Path(__file__).parents[2]

df = pd.read_csv(str(parentDir) + "\\data\\WeakCipherKey.csv", names=["i", "CT"], skiprows=1, delimiter="\t")

df1 = pd.DataFrame(columns=['x', 'y'])

TITLE = "Weak CipherText"
tools = "pan,wheel_zoom,box_zoom,reset,save".split(',')

p = figure(tools=tools)
currentLargestNumber = 15704748922904876457
currentSmallestNumber = 74216662100961077
for index, row in df.iterrows():
    tempNum = row["CT"]
    xCoor = tempNum[0:16]
    yCoor = tempNum[16:32]
    xCoorValue = int(xCoor, 16)
    yCoorValue = int(yCoor, 16)
    df1 = df1.append([{"x": xCoorValue, "y": yCoorValue}], ignore_index=True)

# Used for data normalisation. Puts points between -0.5 to 0.5
df_norm = (df1 - df1.mean()) / (df1.max() - df1.min())

p.background_fill_color = "#dddddd"
p.xaxis.axis_label = "index (i)"
p.yaxis.axis_label = "bit value (bin)"
p.grid.grid_line_color = "white"
p.x_range = Range1d(-0.6, 0.6)

for index, row in df_norm.iterrows():
    x = row["x"]
    y = row["y"]
    p.scatter(x, y, radius=0.01,
              fill_color="#0000ff", fill_alpha=1,
              line_color=None)

output_file("weakAES.html", title="color_scatter.py example")

show(p)  # open a browser
