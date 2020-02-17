from pathlib import Path

import pandas as pd
from bokeh.layouts import gridplot

from bokeh.models import ColumnDataSource, Range1d
from bokeh.plotting import figure, show, output_file


parentDir = Path(__file__).parents[2]

df = pd.read_csv(str(parentDir) + "\\data\\pt.csv", names=["Index", "Tx", "Rx", "CT"], skiprows=1, delimiter="\t")

palette = ["#008000", "#800080", "#000000", "#FF0000"]

TITLE = "AES Synchronisation"
tools = "pan,wheel_zoom,box_zoom,reset,save".split(',')


p = figure(tools=tools, toolbar_location="above", plot_width=1200, plot_height=400, title=TITLE)
p.background_fill_color = "#dddddd"
p.xaxis.axis_label = "index (i)"
p.yaxis.axis_label = "bit value (bin)"
p.grid.grid_line_color = "white"
p.x_range = Range1d(-1, 2)


p1 = figure(tools=tools, toolbar_location="above", x_range=p.x_range, y_range=p.y_range, plot_width=1200,
            plot_height=400, title="Transmission Data")
p1.background_fill_color = "#dddddd"
p1.xaxis.axis_label = "index (i)"
p1.yaxis.axis_label = "bit value (bin)"
p1.grid.grid_line_color = "white"


source = ColumnDataSource(df)

print(source.column_names)

p1.line(x="Index", y="CT", color="#000000", source=source)
p.line(x="Index", y="Rx", color="#0000ff", source=source)
p.line(x="Index", y="Tx", color="#ff0000", source=source)


output_file("AESData.html", title="AES Data.py example")


g = gridplot([[p], [p1]])


show(g)
