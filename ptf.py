#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import click
import subprocess
import os
import sqlite3
from sqlite3 import Error
from datetime import datetime
from tabulate import tabulate
import signal
import nmap
import json

#tornade, nose, tabulate, python-nmap


nmapLight = "nmap.light"
nmapFull = "nmap.full"
niktoTxt = "nikto.txt"
dbFile = ".cache"

@click.group(invoke_without_command=True)
@click.pass_context
@click.option('--help', is_flag=True)
def main(ctx, help):
    if not ctx.invoked_subcommand:
        if help:
            click.echo("""
██╗    ██╗██╗      █████╗ ███╗   ██╗██████╗ ████████╗███████╗
██║    ██║██║     ██╔══██╗████╗  ██║██╔══██╗╚══██╔══╝██╔════╝
██║ █╗ ██║██║     ███████║██╔██╗ ██║██████╔╝   ██║   █████╗  
██║███╗██║██║     ██╔══██║██║╚██╗██║██╔═══╝    ██║   ██╔══╝  
╚███╔███╔╝███████╗██║  ██║██║ ╚████║██║        ██║   ██║     
 ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝   ╚═╝     
 E N T E R P R I S E                       E D I T I O N

    Default Usage: ./wlanPtf scan 10.10.10.10
    Extended usage:
      --nikto    Runs nikto scans on http/s ports detected
      --dirb     Runs dirb scans on http/s ports detected
      --smb      Runs SMB scanning for open shares
      --hailmary Smash and grab, baby. Run everything.
            """)
    pass
global conn
@main.command()
def status():
    global conn
    conn = create_db_connection(False)
    pm = ProcessManager()
    pm.load()
    pm.update()
    click.echo(pm.toString())

@main.command()
@click.option('--help', is_flag=True)
@click.option('--nikto', help='Run a Nikto scan if port 80 is open', is_flag=True)
@click.argument('target')
def scan(help, nikto, target):
    if not target:
        click.echo("Please provide a target. Ex: python ptf.py 10.10.10.91")
    click.echo("Beginning probe scans for {}".format(target))
    
    global conn
    conn = create_db_connection(False)
    prep_db()
    global pm
    pm = ProcessManager()
    pm.load()

    # Start nmap scanning
    #click.echo("Nmap's scanning {}, check {} and {} for output".format(target, nmapLight, nmapFull))
    click.echo("Starting light nmap scan for initial recon...")
    # Asynchronous usage of PortScannerAsync
    
    #run_program("nikto", target, "80", "http", ["nikto", "-h", "http://{}".format(target)])
    #return
    def investigate_service(port, target, service):
        #click.echo("{}: {}".format(port,service))
        service_directory = {}
        http = ["nikto", "-h", "http://{}".format(target)]
        # Port Definitions
        for key in [80, 8080, 443, 8043]:
            service_directory[key] = http
        if port in service_directory:
            run_program(service_directory[port][0], target, port, service["name"], service_directory[port])


    nma = nmap.PortScannerAsync()
    def process_nmap_scan(host, result):
        if result["scan"] and result["scan"][host]:
            services = result["scan"][host]["tcp"]
            if services:
                click.echo("Auto investigating the following identified services. Run `ptf status` for an update.")
                for port in services:
                    investigate_service(port, target, services[port])
            else:
                click.echo("{} doesn't appear to have any open ports!".format(host))
        else:
            click.echo("This host didn't respond, it might be down")
        
        # Go ahead and kick off the intense nmap scan while everything else runs
        run_program("nmapFull", target, "", "", ["nmap",  "-vvv", "-A", "-p-", "-Pn", "--script=all", target])
        click.echo(pm.toString())
        conn.close()
    
    nma.scan(hosts=str(target), arguments='-F -Pn', callback=process_nmap_scan)
    while nma.still_scanning():
        nma.wait(1)


    return
    """ Process simulation w/ cURL """
    run_program("curl", target, "80", "http", ["curl", target+":80"])
    run_program("nmapLight", target, "", "", ["nmap", "-vvv", "-F", target])
    run_program("nmapFull", target, "", "", ["nmap",  "-vvv", "-A", "-p-", "-Pn", "--script=all", target])
    run_program("nikto", target, "80", "http", ["nikto", "-h", "http://{}".format(target)])

@main.command()
@click.argument('pid')
def kill(pid):
    global conn
    conn = create_db_connection()
    pm = ProcessManager()
    pm.load()
    if int(pid) in pm.processes:
        p = pm[int(pid)]
        try:
            if p.kill():
                click.echo("Process " + str(pid) + " successfully killed")
                return
        except:
            click.echo("There was an error killing process " + pid)
            return
    
    click.echo("PID " + str(pid) + " is already down or never existed!")
    conn.close()

@main.command()
def stop():        
    global conn
    conn = create_db_connection()
    pm = ProcessManager()
    pm.load()
    conn.close()
    for pid in pm.processes:
        p = pm[pid]
        p.kill()
    click.echo("Killed PIDs from previous runs")

@main.command()
def cleanup():        
    global conn
    conn = create_db_connection()
    pm = ProcessManager()
    pm.load()
    conn.close()
    for pid in pm.processes:
        p = pm[pid]
        p.kill()
        if os.path.isfile(p.output):
            os.remove(p.output)

    click.echo("Killed PIDs from previous runs")
    click.echo("Cleaned up files from previous runs")

    # TODO: [Duplicate Code] Call the dropdb function below instead of this
    if os.path.isfile(dbFile):
        os.remove(dbFile)
        click.echo('Dropped the database')

def run_program(program, target, port, service, command=[]):
    #click.echo("{}, {}, {}, {}, {}".format(program, target, port, service, command))
    fileName = program+str(port)+".txt"
    with open(fileName, "w+") as file:
        proc = subprocess.Popen(command, stdout=file, stderr=file)
        pm.add(Process(proc.pid, program, target, port, service, fileName))

""""""""""""""""""""""""""
""" DATABASE OPERATIONS """
""""""""""""""""""""""""""
@main.command()
def dropdb():
    if os.path.isfile(dbFile):
        os.remove(dbFile)
    click.echo('Dropped the database')

def create_db_connection(reset=False):
    """ Cleanup db from previous run """
    if reset and os.path.isfile(dbFile):
        click.echo("DB Found, deleting...")
        os.remove(dbFile)
    try:
        conn = sqlite3.connect(dbFile)
    except Error as e:
        print(e)
    return conn

def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)

""" Prepares a blank database for use with wlanPtf """
def prep_db():
    sql_create_process_table = """ CREATE TABLE IF NOT EXISTS process (
                                pid int PRIMARY KEY,
                                name text NOT NULL,
                                target text NOT NULL,
                                port text NOT NULL,
                                service text NOT NULL,
                                output text,
                                start_time text NOT NULL,
                                status text
                            ); """
    create_table(conn, sql_create_process_table)

""""""""""""""""""""""""""
""" PROCESS MANAGEMENT """
""""""""""""""""""""""""""
class ProcessManager:
    def __init__(self):
        self.processes = {}
    
    def __getitem__(self, item):
        return self.processes[item]
    
    def add(self, process):
        self.processes[process.pid] = process
    
    def load(self):
        c = conn.cursor()
        try:
            c.execute('SELECT * FROM process')
            for process in c.fetchall():
                newProcess = Process(*process)
                newProcess.update()
                self.add(newProcess)
        except sqlite3.Error as er:
            if "no such table" in er.message: #TODO: Make this better...
                prep_db()
    
    # Update's the status of each process
    def update(self):
        for pid in self.processes:
            self.processes[pid].update()

    def saveAll(self):
        for p in self.processes:
            p.save()

    def toString(self):
        headers = ['PID', 'Name', 'Target', 'Port', 'Service', 'Output', 'Start', 'End', 'Status']
        processes = [ v for v in self.processes.values() ] #Converts process dict to list
        processesValueList = list(map(lambda p: p.toList(), processes)) #Converts list to multi array of process values
        return click.echo(tabulate(processesValueList, headers=headers, tablefmt='psql')) #Pretty prints to table format

class Process:
    def __init__(self, pid, name, target, port, service, output=None, start_time=None, status=None):
        self.pid = pid
        self.name = name
        self.target = target
        self.port = port
        self.service = service
        self.output = output
        self.start_time = datetime.today().strftime('%-I:%M:%S %p') if start_time == None else start_time
        self.status = "Running" if check_pid(self.pid) else "Ended"
        self.save()
    
    def save(self):
        conn = create_db_connection() #TODO: This might get mad slow later on, but without it I seem to get a MemoryError sometimes
        c = conn.cursor()
        count = c.execute('SELECT count(*) FROM process WHERE pid = ?', [self.pid])
        if count.fetchone()[0] == 0:
            c.execute('insert into process values (?,?,?,?,?,?,?,?)', self.toList())
        else:
            c.execute('update process SET name = ?, target = ?, port = ?, service = ?, output = ?, start_time = ?, status = ? WHERE pid = ?', 
                      [self.name, self.target, self.port, self.service, self.output, self.start_time, self.status] + [self.pid])
        conn.commit()
        conn.close()

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL) #or signal.SIGKILL
            return True
        except OSError as e:
            return False

    def update(self):
        #click.echo(check_pid(self.pid))
        self.status = "Running" if check_pid(self.pid) else "Ended"

    def toList(self):
        return [self.pid, self.name, self.target, self.port, self.service, self.output, self.start_time, self.status]

""""""""""""""
""" UTILS """
""""""""""""""

def check_pid(pid):       
    """ Check For the existence of a unix pid. """
    if os.name == "posix":
        ps = subprocess.Popen(["ps", "-p", str(pid)], stdout=subprocess.PIPE).stdout
        return str(pid) in ps.read().decode()
    else:
        return os.path.exists("/proc/%d"%(pid))

if __name__ == "__main__":
    main()
