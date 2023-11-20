#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 23 20:31:27 2023

@author: halimekaya
"""

import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt


data1 = pd.read_csv("sample.csv")

#######################################################################################

try:
  
    data1.head(20)
    
    data1 = data1[data1['Risk'] != 'None']
    
except FileNotFoundError:
    print("Could not retrieve first 20 data")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")

#########################################################

#########################################################

try:

    top_hosts = data1['Host'].value_counts().head(5)
    

    print(top_hosts)
    
   
    
    
   
    top_hosts = data1['Host'].value_counts().head(5)
    
    
    plt.figure(figsize=(8, 6))
    
   
    ax = top_hosts.plot(kind='barh', stacked=True)
    
   
    ax.set_prop_cycle('color', plt.cm.Dark2.colors)
    
    
    plt.title('5 Hosts with the Most Vulnerabilities', fontsize=14)
    plt.xlabel('Count', fontsize=12)
    plt.ylabel('Host', fontsize=12)
    plt.tick_params(axis='both', which='major', labelsize=12, width=1)
    
   
    for i, v in enumerate(top_hosts):
        ax.text(v + 0.1, i - 0.1, str(v), fontsize=12)
    
   
    plt.savefig('barchart.png', bbox_inches='tight')

except FileNotFoundError:
    print("The 5 most repeated hosts were not found")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")

#########################################################


try:
   
   
    filtered_data1 = data1[data1['Risk'].isin(['High', 'Critical'])]
    risk_counts = filtered_data1['Risk'].value_counts()
    
    
    
   
    fig, ax = plt.subplots()
    wedges, labels = ax.pie(risk_counts, startangle=90, textprops=dict(color="w", fontsize=12))
    
   
    colors = ['pink', 'red']
    for i, wedge in enumerate(wedges):
        wedge.set_facecolor(colors[i])
    
  
    legend_labels = ['High', 'Critical']
    legend = ax.legend(wedges, legend_labels, title='Risk Severities', loc='center left', bbox_to_anchor=(1, 0, 0.5, 1))

    for text, color in zip(legend.get_texts(), colors):
        text.set_color(color) 
    
        
    plt.title('Total', fontsize=14)
    

    fig.savefig('pgf.png', dpi=300, bbox_inches='tight')
    
except FileNotFoundError:
    print("Risk Severities not found")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")

#########################################################

try:
   
    
    filtered_data1 = data1[data1['Risk'].isin(['Critical','High'])]
    risk_counts = filtered_data1['Risk'].value_counts()
    risk_table = pd.DataFrame({'Risk Severity': risk_counts.index, 'Count': risk_counts.values})
    
   
    print(risk_table)
    

    cell_colors = []
    for i, row in risk_table.iterrows():
       
        if row['Risk Severity'] == 'Critical':
            cell_colors.append(['red', 'w'])
        elif row['Risk Severity'] == 'High':
            cell_colors.append(['pink', 'w'])
        else:
            cell_colors.append(['blue', 'w'])
    
    
    fig, ax = plt.subplots()
    ax.axis('off')
    table = ax.table(cellText=risk_table.values, colLabels=risk_table.columns, loc='center', cellLoc="center", cellColours=cell_colors)
    
  
    table.auto_set_font_size(False)
    table.set_fontsize(14)
    table.scale(1, 2)
    
    
    plt.savefig('risk_table.png', dpi=300, bbox_inches='tight')
    
except FileNotFoundError:
    print("Risk data not found")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")

#########################################################
#########################################################


try:
    
    filtered_data1 = data1[data1['Risk'].isin(['High', 'Critical'])]
    
    
    top_5_solution = filtered_data1['Solution'].value_counts().nlargest(5)
    
    
    table_data = {'Solution': top_5_solution.index, 'Count': top_5_solution.values}
    table_df = pd.DataFrame(data=table_data)
    
    max_solution_length = 100  
    table_df['Solution'] = table_df['Solution'].apply(lambda x: x[:max_solution_length] + '...' if len(x) > max_solution_length else x)
    
    
    cell_colours = [['lightgray', 'lightgray']]*len(table_df.index)
    
    
    
    fig, ax = plt.subplots(figsize=(15, 6))
    ax.axis('off')
    ax.axis('tight')
    table = ax.table(cellText=table_df.values, colLabels=table_df.columns, loc='center', cellLoc="center", cellColours=cell_colours)
    table.set_fontsize(10)
    table.scale(2, 4.5)
    table.auto_set_column_width(col=list(range(len(table_df.columns))))
    
    fig.suptitle('Most Recommended Improvements', y=1.0, fontsize=12)
    
    plt.savefig('top5_solutions.png', dpi=600, bbox_inches='tight')
    
except FileNotFoundError:
    print("Solution data nto found")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")

#########################################################



try:

        filtered_data1 = data1[data1['Risk'].isin(['High', 'Critical'])]
        top_5_name = filtered_data1['Name'].value_counts().nlargest(5)
        

        table_data = {'Name': top_5_name.index, 'Count': top_5_name.values}
        table_df = pd.DataFrame(data=table_data)
        

        cell_colours = [['lightgray', 'lightgray']]*len(table_df.index)

        fig, ax = plt.subplots(figsize=(15, 6))
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=table_df.values, colLabels=table_df.columns, loc='center', cellLoc="center", cellColours=cell_colours)
        table.set_fontsize(12)
        table.scale(2, 2.5)
        table.auto_set_column_width(col=list(range(len(table_df.columns))))
        
        fig.suptitle('List of Most Common Vulnerabilities', y=0.8, fontsize=12)
        plt.savefig('top5_name.png',dpi=600, bbox_inches='tight')
        
except FileNotFoundError:
    print("Name data not found")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")
#########################################################
try:

        
        filtered_data1 = data1[data1['Risk'].isin(['High', 'Critical'])]
        top_5_cve = filtered_data1['CVE'].value_counts().nlargest(5)
        
 
        table_data = {'CVE': top_5_cve.index, 'Count': top_5_cve.values}
        table_df = pd.DataFrame(data=table_data)
        

        
        cell_colours = [['lightgray', 'lightgray']]*len(table_df.index)
  
        fig, ax = plt.subplots(figsize=(15, 6))
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=table_df.values, colLabels=table_df.columns, loc='center', cellLoc="center", cellColours=cell_colours)
        table.set_fontsize(12)
        table.scale(1, 2.5)
        #table.auto_set_column_width(col=list(range(len(table_df.columns))))
        
        fig.suptitle('Most CVEs', y=0.8, fontsize=12)
        plt.savefig('top5_cve.png',dpi=600, bbox_inches='tight')

except FileNotFoundError:
    print("cve data not found")
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")

#########################################################

plt.close('all')

############################################################################################

##########################################################################################

from reportlab.pdfgen import canvas
from reportlab.lib.units import inch,cm
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.lib import utils
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import os


page_size = A4
c = canvas.Canvas("nessus_report.pdf", pagesize=page_size) 
############################################################################################

cover_page = "cover_page.png"
width, height = c.drawImage(cover_page, 0, 0, page_size[0], page_size[1])


if width > page_size[0] or height > page_size[1]:
    width_ratio = width / page_size[0]
    height_ratio = height / page_size[1]
    if width_ratio > height_ratio:
        width = page_size[0]
        height = height / width_ratio
    else:
        height = page_size[1]
        width = width / height_ratio

x = (page_size[0] - width) / 2
y = (page_size[1] - height) / 2
c.drawImage(cover_page, x, y, width=width, height=height)

############################################################################################

############################################################################################
c.showPage() 


c.setFont("Helvetica-Bold", 20)
c.drawString(2.5*inch, 11*inch, "Tables and Graphs")



try:

    grafik = ImageReader("pgf.png")
    c.drawImage(grafik, 50, 475, width=250, height=250)

except FileNotFoundError:
    print("pgf.png not found.")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...") 

try:

 
    tablo = ImageReader("risk_table.png")
    c.drawImage(tablo, 300, 475, width=250, height=250)

except FileNotFoundError:
    print("risk_table.png not found.")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...") 

try:


    grafik2 = ImageReader("barchart.png")
    c.drawImage(grafik2, 50, 200, width=400, height=200)

except FileNotFoundError:
    print("barchart.png not found.")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...") 


############################################################################################


try:
    c.showPage()
    

    WIDTH, HEIGHT = A4
    img_width, img_height = WIDTH, HEIGHT / 3
    img1 = ImageReader("top5_name.png")
    c.drawImage(img1, 0, HEIGHT - img_height, img_width, img_height)
except FileNotFoundError:
    print("top5_name.png not found.")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...") 
    
try:    
  
    img2 = ImageReader("top5_cve.png")
    c.drawImage(img2, 0, HEIGHT - 2*img_height, img_width, img_height)
        
except FileNotFoundError:
    print("top5_cve.png not found.")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...") 

try:   
    # Üçüncü görseli canvas'a ekle
    img3 = ImageReader("top5_solutions.png")
    c.drawImage(img3, 0, HEIGHT - 3*img_height, img_width, img_height)
    # 3 adet görseli A4 boyutuna sığdırarak canvas'a ekle

except FileNotFoundError:
    print("top5_solutions.png not fount.")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")   


###########################################################################################
###########################################################################################

try:
    
    c.showPage()
    c.setFont("Helvetica-Bold", 24)
    c.drawString(230, 800, "Vulnerability Information")
    
    
   
    df_filtered2 = data1.loc[data1["Risk"].isin(["Critical", "High"]), ["Risk","Description","Solution", "Name", "CVSS v2.0 Base Score","Host"]]
    df_grouped2 = df_filtered2.groupby(["Risk", "Name","Description","Solution", "CVSS v2.0 Base Score"])["Host"].apply(lambda x: ', '.join(x)).reset_index()
  
    df_filtered2 = df_filtered2.drop_duplicates(subset=["Name"])
    
    df_grouped2 = df_grouped2.sort_values(by=["Risk", "CVSS v2.0 Base Score"], ascending=[True, False])
    
    
    df_grouped2 = df_grouped2.head(20)
    
    y = 750
    line_height = 15
    
    for index, row in df_grouped2.iterrows():
        
        name = row['Name']
        risk = row['Risk']
        description = row['Description']
        solution = row['Solution']
        host = row['Host']
        
       
      
        c.setFont("Helvetica", 12)
        c.drawCentredString(A4[0] / 2, y-40, risk)
        
         
    
        c.setFont("Helvetica", 12)
        c.drawCentredString(A4[0] / 2, y-40, risk)
        
        name_y = y - 60
        c.setFont("Helvetica-Bold", 12)
        for line in name.split('\n'):
            if c.stringWidth(line, "Helvetica-Bold", 12) < A4[0]-100:
                c.drawCentredString(A4[0] / 2, name_y, line)
                name_y -= 16
            else:
                words = line.split()
                new_line = ""
                for word in words:
                    if c.stringWidth(new_line + " " + word, "Helvetica-Bold", 12) < A4[0]-100:
                        new_line += " " + word
                    else:
                        c.drawCentredString(A4[0] / 2, name_y, new_line)
                        name_y -= 16
                        new_line = word
                c.drawCentredString(A4[0] / 2, name_y, new_line)
                name_y -= 16
    
        
    
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y-150, "Description:")
        
      
        c.setFont("Helvetica", 10)
        description_y = y - 180
        merged_lines = []
        for line in description.split('\n'):
            if c.stringWidth(line, "Helvetica", 10) > A4[0]-100:
                words = line.split()
                new_line = ""
                for word in words:
                    if c.stringWidth(new_line + " " + word, "Helvetica", 10) < A4[0]-100:
                        new_line += " " + word
                    else:
                        merged_lines.append(new_line)
                        new_line = word
                merged_lines.append(new_line)
            else:
                merged_lines.append(line)
        for line in merged_lines:
            font_size = 10
            font_height = font_size + 4
            description_lines = font_height * len(line) / (A4[0]-100)
            if description_y - description_lines*font_height < 50:
                c.showPage()
                description_y = A4[1] - 50
            c.setFont("Helvetica", font_size)
            c.drawString(50, description_y, line)
            description_y -= font_height
    
    
    
        
     
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, description_y-30, "Solution:")
        
    
        c.setFont("Helvetica", 10)
        solution_y = description_y - 60
        merged_lines = []
        for line in solution.split('\n'):
            if c.stringWidth(line, "Helvetica", 10) > A4[0]-100:
                words = line.split()
                new_line = ""
                for word in words:
                    if c.stringWidth(new_line + " " + word, "Helvetica", 10) < A4[0]-100:
                        new_line += " " + word
                    else:
                        merged_lines.append(new_line)
                        new_line = word
                merged_lines.append(new_line)
            else:
                merged_lines.append(line)
        for line in merged_lines:
            font_size = 10
            font_height = font_size + 4
            solution_lines = font_height * len(line) / (A4[0]-100)
            if solution_y - solution_lines*font_height < 50:
                c.showPage()
                solution_y = A4[1] - 50
            c.setFont("Helvetica", font_size)
            c.drawString(50, solution_y, line)
            solution_y -= font_height
            
            
      
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, solution_y-30, "Hosts:")
        
        c.setFont("Helvetica", 10)
        host_y = solution_y - 60
        merged_lines = []
        unique_hosts = set()  
        
        for line in host.split('\n'):
            unique_hosts.update(line.split(", "))  
        
   
        for host_line in unique_hosts:
            if c.stringWidth(host_line, "Helvetica", 10) > A4[0] - 100:
                words = host_line.split()
                new_line = ""
                for word in words:
                    if c.stringWidth(new_line + " " + word, "Helvetica", 10) < A4[0] - 100:
                        new_line += " " + word
                    else:
                        merged_lines.append(new_line)
                        new_line = word
                merged_lines.append(new_line)
            else:
                merged_lines.append(host_line)
        
        for line in merged_lines:
            font_size = 10
            font_height = font_size + 4
            host_lines = font_height * len(line) / (A4[0] - 100)
            if host_y - host_lines * font_height < 50:
                c.showPage()
                host_y = A4[1] - 50
            c.setFont("Helvetica", font_size)
            c.drawString(50, host_y, line)
            host_y -= font_height
    
            
         
        c.showPage()

except FileNotFoundError:
    print("vunerabilities details not found")
    
except Exception as e:
    print("Something went wrong:", e)


print("The program continues...")     





c.save() 

plt.close('all')






















