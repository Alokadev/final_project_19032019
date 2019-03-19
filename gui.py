from  functions import *

#
# ===============Master=================================================================================================
#

master = Tk()
master.title('Network Security')
master.geometry('640x480+50+100')
master.resizable(False, False)
master.configure(background='#e1d8b9')

#
# ===============ttk.style reconfigure==================================================================================
#

style = ttk.Style()
style.configure('TFrame', background='#e1d8b9')
style.configure('TButton', background='#e1d8b9')
style.configure('TLabel', background='#e1d8b9', font=('Arial', 11))
style.configure('Header.TLabel', font=('Arial', 18, 'bold'))

#
# ===============frame header===========================================================================================
#

frame_header = ttk.Frame(master, width=600)
frame_header.pack()

# Image configuration
logo = PhotoImage(file='tour_logo.gif')
ttk.Label(frame_header, image=logo).grid(row=0, column=0, rowspan=2)

# Lable configuration
ttk.Label(frame_header, text='Network Security', style='Header.TLabel').grid(row=0, column=1)
ttk.Label(frame_header,text=("Easy Network Analysing Tool with Easy GUI.  "
                        )).grid(row=1, column=1)

#
# ===============content================================================================================================
#

frame_content = ttk.Frame(master)
frame_content.pack()

notebook = ttk.Notebook(master, width=600, height=320)
notebook.pack()
default_info = ttk.Frame(notebook)
block_ = ttk.Frame(notebook)
web_scan = ttk.Frame(notebook)
notebook.add(default_info, text='Default Info')
notebook.add(block_, text='Subnet Scanner')
notebook.add(web_scan, text='Web Scanning')



treeview = ttk.Treeview(default_info, selectmode="extended")
treeview.pack(expand=YES, fill=BOTH)
treeview.column("#0", minwidth=0, width=600, stretch=NO)
treeview.heading("#0", text="Informations about default interface of this Machine", anchor = 'center')

treeview.insert('', 1, 'item'+str(1), text=('GUID value of Interface            : ' + default_int_details()['interface']))
treeview.insert('', 2, 'item'+str(2), text=('IP Address of Interface             : ' + default_int_details()['address']))
treeview.insert('', 3, 'item'+str(3), text=('Networkmask of Interface       : ' + default_int_details()['netmask']))
treeview.insert('', 4, 'item'+str(4), text=('Network of Interface                : ' + default_int_details()['cidr']))
treeview.insert('', 5, 'item'+str(5), text=('Broadcast IP of Network          : ' + default_int_details()['broadcast']))
treeview.insert('', 6, 'item'+str(6), text=('MAC Address of interface       : ' + default_int_details()['macaddress']))
treeview.insert('', 7, 'item'+str(7), text=('Network name of interface     : ' + default_int_details()['netid']))
treeview.insert('', 8, 'item'+str(8), text=('Router IP                                    : ' + default_int_details()['default']))

treeview = ttk.Treeview(block_, selectmode="extended")
treeview.pack(expand=YES, fill=BOTH)
treeview.column("#0", minwidth=0, width=600, stretch=NO)
treeview.heading("#0", text="\tIP\t\t        MAC Address\t\tVender", anchor = 'w')

ttk.Button(frame_content, text='Check Network',
           command= lambda:check(treeview)).grid(row=4, column=0, padx=5, pady=5, sticky='e')

def check(treeview):
    for i in treeview.get_children():
        treeview.delete(i)
    result = default_int_details()['cidr']
    print(result)
    result = scan(result)
    num = -1
    for client in result:
        num = num+1
        treeview.insert('', num, 'item'+str(num), text=(client["ip"] +
                                                        "\t\t" + client["mac"] + "\t\t" + client["vender"]))


#arp_avoider()
# arp_avoider_router()
master.mainloop()

#
#=======================================================================================================================
#