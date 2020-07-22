#### Parser Content
```Java
{
Name = cisco-asa-connection-stop
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection-stop"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "%ASA-", "-30202", "Teardown ", " connection " ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d+)""",
    """(\w{3} (\d\d| \d) \d\d\d\d (\d\d| \d):\d\d:\d\d)\s+({host}[\w\.-]+)\s*:\s*%ASA-""",
    """%ASA-({priority}\d+)-({event_code}\d+)""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sfaddr\s+((({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))((\/({dest_port}\d+))|(\s|$))|({icmp_seq_num}\S+))""",
    """\sgaddr\s+((({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_translated_host}[^\s]+?))((\/({dest_translated_port}\d+))|(\s|$))|({icmp_type}\S+))""",
    """\sladdr\s+(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))((\/({src_port}\d+))|(\s|$))""",
    """for\s+[^\s:]+:\s*((({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))((\/({src_port}\d+))|(\s|$))|({icmp_type}\S+))""",
    """to\s+[^\s:]+:\s*(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))((\/({dest_port}\d+))|(\s|$))""", 
    """\sbytes\s+({bytes}\d+)""",
    """%ASA-.*?\((({domain}[^\\\/]+)[\\\/]+)?(?:({user_email}[^@\\\/]+@[^@\\\/]+?)|({user}[^\\\/]+?))\)"""
  ]
  DupFields = [ "event_name->activity" ]
}

{
  Name = cisco-ftd-connection-stop
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection-stop"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "%FTD-", "-30202", "Teardown ", " connection " ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s*:\s*%FTD-""",
    """%FTD-({priority}\d+)-({event_code}\d+)""",
    """({event_name}Teardown ({protocol}\w+) connection)""",
    """\sfaddr\s+((({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))((\/({dest_port}\d+))|(\s|$))|({icmp_seq_num}\S+))""",
    """\sgaddr\s+((({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_translated_host}[^\s]+?))((\/({dest_translated_port}\d+))|(\s|$))|({icmp_type}\S+))""",
    """\sladdr\s+(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))((\/({src_port}\d+))|(\s|$))""",
    """for\s+[^\s:]+:\s*((({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({src_host}[^\s]+?))((\/({src_port}\d+))|(\s|$))|({icmp_type}\S+))""",
    """to\s+[^\s:]+:\s*(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|({dest_host}[^\s]+?))((\/({dest_port}\d+))|(\s|$))""", 
    """\sbytes\s+({bytes}\d+)""",
    """%FTD-.*?\((({domain}[^\\\/]+)[\\\/]+)?(?:({user_email}[^@\\\/]+@[^@\\\/]+?)|({user}[^\\\/]+?))\)"""
  ]
  DupFields = [ "event_name->activity" ]
}

{
  Name = cisco-process-network
  Vendor = Cisco
  Product = AnyConnect
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ pn=""", """ ppn=""", """fv=nvzFlow_v3""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\sfet='*(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d\d:\d\d:\d\d \d+)""",
    """\ssa="({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\ssa="({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sda="({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\ssp=({src_port}\d+)""",
    """\sdp=({dest_port}\d+)""",
    """\sibc=({bytes_in}\d+)""",
    """\sobc=({bytes_out}\d+)""",
    """\spr=({packet_rate}\d+)""",
    """\spn='*(?=\w)({process_name}[^']+)'*\s""",
    """\sppn='*(?=\w)({parent_process_name}[^']+)'*\s""",
    """\spph="({parent_process_hash}([^"]+))"""",
    """\sdh="({dest_host}([^"]+))"""",
    """\sph="?({process_hash}([^\s]+))"?\s""",
    """\sppap='(?:[^']+[\s])?'*({user}[^\s']+)""",
    """\sppaa='(?:[^']+[\s])?'*({domain}[^\s']+)""",
    """\spaa='(?:[^']+[\s])?'(?:[^']+[\s])?({domain}[^\s']+)""",
    """\spap='(?:[^']+[\s])?'(?:[^']+[\s])?({user}[^\s']+)""",
    """\sudid=({udid}([^\s]+))\s""",
    """\smnl='(?=\w)({module_hash_names}[^']+?)\s*'\s""",
    """\svsn=({virtual_station_name}[^\s]+)\s""",
    """\sosn=({os_name}[^\s]+)""",
    """\sosv=({os_version}[^\s]+)\s""",
    """\sose=({os_environment}[^\s]+)\s""",
    """\ssm=({system_manufacturer}[^\s]+)\s""",
    """\sst=({system_type}[^\s]+)\s"""
  ]
}
```