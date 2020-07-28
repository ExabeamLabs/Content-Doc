#### Parser Content
```Java
{
Name = aruba-controller-failed-nac-logon
  Vendor = HP Aruba
  Product = Aruba Wireless controller
  Lms = Splunk
  DataType = "nac-failed-logon"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """authmethod=""", """servername=""", """apname=""", """bssid=""", """Authentication failed""" ]
  Fields = [
   """({time}\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
   """\d\d\d\d\s+({host}[^\s]+)\s(authmgr|stm)\[({event_code}\d+)\]""",
   """username=({user}[^\s]+)""",
   """userip=({src_ip}[a-f0-9.]+)""",
   """usermac=({src_mac}[a-f0-9:]+)""",
   """bssid=({ssid}[a-f0-9:]+)""",
   """serverip=({auth_server}[a-f0-9.]+)""",
   """authmethod=({auth_method}[^\s]+)""",
   """User\sAuthentication\s({outcome}[\w]+)"""
  ]
}
{
  Name = cef-cloudflare-net-connection
  Vendor = Cloudflare
  Product = Cloudflare
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""", """destinationServiceName=Cloudflare""", """dproc=Firewall""" ]
  Fields = [
    """ext__occurred_at_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """ext_action=({activity}[^\s]+)\s""",
    """suser=({user}[^\s]+)\s""",
    """ext_ua=({user_agent}.*?)\s*\w+=""",
    """ext_country=({country_code}.*?)\s*\w+=""",
    """deviceInboundInterface=({src_interface}.*?)\s*\w+=""",
    """dhost=({original_dest_host}.*?)\s+\w+=""",
    """dproc=({process}.*?)\s*\w+=""",
    """ext_proto=({protocol}.*?)\s*\w+=""",
    """reason=({failure_reason}.*?)\s*\w+=""",
    """deviceDirection=({direction}.*?)\s*\w+=""",
    """dpt=({dest_port}\d+)\s""",
    """spt=({src_port}\d+)\s""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """destinationDnsDomain=({external_domain}.*?)\s*\w+=""",
    """requestClientApplication=({app}.+?)\s*\w+=""",
    """ext_source=({log_source}.+?)\s*\w+=""",
    """\sin=({bytes}.+?)\s*\w+=""",
    """ext_method=({method}[^\s]+)""",
    """cat=({category}[^\s]+)\s""",
    """cn2=({bytes}[^\s]+)\s""",
    """destinationServiceName=({dest_host}[^\s]+)\s"""
 ]
}

${ClearSenseParserTemplates.clesarsense-app-activity}{
  Name = clearsense-app-login
  DataType = "app-login"
  Conditions = [ """SUCCESSFUL_LOGIN""", """Login Successful""", """requestClientApplication=ClearSense Audit""", """CEF""" ]
}
${ClearSenseParserTemplates.clesarsense-app-activity}{
  Name = clearsense-app-activity
  DataType = "app-activity"
  Conditions = [ """requestClientApplication=ClearSense Audit""", """CEF""" ]
}

{
  Name = infoblox-bloxone-dns-response 
  Vendor = Infoblox BloxOne
  Product = Infoblox BloxOne
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""|Infoblox|""", """app=DNS""", """InfobloxDNSView=""", """InfobloxDNSQType=""" ]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """src=(\s|({src_ip}[a-fA-F\d.:]+))""",
     """dst=(\s|({dest_ip}[a-fA-F\d.:]+))""",
     """spt=(\s|({src_port}\d+))""",
     """proto=(\s|({protocol}[^\s]+))""",
     """app=({app}[^\s]+)""",
     """InfobloxDNSRCode=({dns_response_code}[^\s]+)\s""",
     """InfobloxDNSQType=(\s|({query_type}[^\s]+))""",
     """destinationDnsDomain=(\s|({query}[^\s]+))""",
     """msg=(\s|({additional_info}.+?));\s\.\s32768""",
  ]
}
```