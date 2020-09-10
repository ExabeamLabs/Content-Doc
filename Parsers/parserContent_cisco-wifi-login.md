#### Parser Content
```Java
{
Name = cisco-wifi-login
  Vendor = Cisco
  Product = Cisco WiFi
  Lms = Direct
  DataType = "logon"
  TimeFormat = "yyyy年  MM月 dd日 金曜日 HH:mm:ss"
  Conditions = [ """ ccx-client """ , """EAP-Assoc""", """日 金曜日 """ ]
  Fields = [
    """\[({time}\d{4}年  \d+月 \d+日 金曜日 \d\d:\d\d:\d\d)""",
    """\[({dest_ip}[a-fA-F\d\.:]+)\]\s({dest_mac}[a-fA-F\d\.:]+)\s\S+\s+::\s+ccx-client\s+({host}\S+)""",
  ]
  DupFields = [ "host->auth_server" ]
}

{
  Name = firepower-network-alert-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [""" SFIMS: """, """ Sinkhole: """, """ OriginalClientIP: """]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+)\s+SFIMS:""",
    """\WProtocol:\s*({protocol}[^,]+)\s*(,|$)""",
    """\WSrcIP:\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WDstIP:\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\WSrcPort:\s*({src_port}\d+)""",
    """\WDstPort:\s*({dest_port}\d+)""",
    """\WIngressZone:\s*({ingress_zone}[^,]+)\s*(,|$)""",
    """\WEgressZone:\s*({egress_zone}[^,]+)\s*(,|$)""",
    """\WDE:\s*({engine_name}[^,]+)\s*(,|$)""",
    """\WRevision:\s*({revision}[^,]+)\s*(,|$)""",
    """\WPolicy:\s*({policy}[^,]+)\s*(,|$)"""
    """\WAccessControlRuleAction:\s*({outcome}[^,]+)""",
    """\WUserName:\s*({user}[^,]+)""",
    """InitiatorBytes:\s*({bytes_in}\d+)""",
    """\WResponderBytes:\s*({bytes_out}\d+)""",
    """NAPPolicy:\s*({nap_policy}[^,]+)""",
    """\sDNSQuery:\s*({query}[^,]+)""",
    """\WDNSResponseType:\s*({response_type}[^,]+)""",
    """\sDNSRecordType:\s*({query_type}[^,]+)""",
    """URLCategory:\s*({category}[^,]+)""",
    """\WURLReputation:\s*({reputation}[^,]+?)(,|\s*$)""",
  ]
}

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