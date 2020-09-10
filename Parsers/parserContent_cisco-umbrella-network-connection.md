#### Parser Content
```Java
{
Name = cisco-umbrella-network-connection
  Vendor = Cisco
  Product = Proxy Umbrella
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName=Cisco Umbrella """, """dproc=IP """, """"identity":"""" ]
  Fields = [
    """\W(destinationServiceName|requestClientApplication)=({app}.+?)(\s+\w+=|\s*$)""",
    """"timestamp"+:"+({time}[^",]+)"""",
    """({host}[\w\-.]+)\s+Skyformation """,
    """\Wsuser=(anonymous|({user}.+?))(\s+\w+=|\s*$)""",
    """"categories"+:\["+({category}[^",]+)""",
    """"sourceIp"+:"+({src_ip}[^"]+)"""",
    """"sourcePort"+:"+({src_port}\d+)"""",
    """"destinationIp"+:"+({dest_ip}[^",]+)"""",
    """"destinationPort"+:"+({dest_port}\d+)""",
    """"identity"+:"+({dest_host}[^"]+)"""",
  ]
}

{
  Name = cisco-nac-logon-3
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Conditions = [ """ CISE_TACACS_Accounting """, """ TACACS+ Accounting START""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d (\+|-)\d\d:\d\d)""",
    """({host}[^\s]+)\s*CISE_TACACS_Accounting""",
    """({event_name}CISE_TACACS_Accounting)""",
    """Host:\s*({host}\S+)""",
    """, NetworkDeviceName=({network}[^,]+),""",
    """, Device IP Address=({auth_server}[^,]+)""",
    """, Device IP Address=({dest_ip}[a-fA-F\d.:]+)""",
    """, NetworkDeviceGroups=Location#All Locations#({location}[^,]+)""",
    """\sService=({service}[^,]+)""",
    """\sUser=({user}[^,]+)""",
    """\sRemote-Address=({src_ip}[^,]+)""",
    """\sPort=({src_port}\d+)""",
    """\sAuthen-Method=({auth_method}[^,]+)""",
    """\sAcsSessionID=({session_id}[^,]+)""",
  ]
}
```