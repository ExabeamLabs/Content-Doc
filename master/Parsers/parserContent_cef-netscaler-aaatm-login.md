#### Parser Content
```Java
{
Name = cef-netscaler-aaatm-login
  Vendor = Netscaler
  Product = Netscaler VPN
  Lms = Direct
  TimeFormat = "epoch"
  DataType = "remote-login"
  Conditions = [ """AAATM LOGIN""" ]
  Fields = [
    """User\s+({domain}[^\\]+)\\+({user}[^\s]+)"""
    """Client_ip\s+({src_ip}[^\s]+)""",
    """Vserver\s+(127.0.0.1|({host}[^:\s]+))"""
    """Browser_type\s+"+({user_agent}[^"]+)""",
    """SessionId:\s+({session_id}\d+)"""
    """rt=({time}\d+)"""
  ]
  DupFields = ["host->dest_host"]
}

{
 Name = netscalar-remote-access
 Product =Netscaler VPN
 Vendor =Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """ After Initialization """ ]
 Fields =[
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)\s+({host}[\w.\-]+)(\s+\S+){3}\s+({log_type}SSLVPN Message)?\s.*?user\s*({user}[^\s]+)\s*clientip\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*(request:\s*({action}[^\s]+))?""",
   """SSO\s+({event_name}[^:]+): After Initialization user ({user}.+?)\s+clientip\s+(127.0.0.1|({src_ip}[^\s]+))\s"""
  """({event_name}ns_sslvpn_process_sso_conn)""" 
 ]
}

{
 Name = netscalar-remote-access-1
 Product =Netscaler VPN
 Vendor =Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """ SSLVPN """ , """ HTTPREQUEST """ ]
 Fields =[
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s+({host}[\w.\-]+)(\s+\S+){3}\s+({log_type}SSLVPN HTTPREQUEST)?.*?Context\s*(({user_email}[^@]+@[^@]+)|({user}[^@]+))@({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+-\s*SessionId:\s+({session_id}[^\s]+)\s*-\s*({dest_host}.*?)\s+User.*?\s*Vserver\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d+).*?SSO[^:]+:\s*({method}[^\s]+)\s+({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?\s+""",
   """({event_name}HTTPREQUEST)"""
 ]
}

{
 Name = netscalar-remote-access-2
 Product =Netscaler VPN
 Vendor =Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """|SSLVPN""" , """|HTTPREQUEST|""" ]
 Fields =[
    """exabeam_host=({host}[\w\-.]+)""",
    """2020/04/06:03:06:13({time}\d\d\d\d\/\d\d\/\d\d:\d\d:\d\d:\d\d)"""
    """User\s+({user}[^\s]+)"""
    """Vserver\s+(127.0.0.1|({host}[^:\s]+))"""
    """SSO is ON\s*:\s*({method}[^\s]+)\s+({object}[^\-\s]+)""",
    """SessionId:\s+({session_id}\d+)"""
    """({event_name}HTTPREQUEST)""",
    """ahost=({src_host}[^\s]+)""",
 ]
}

{
  Name = netscaler-web-activity-1
  Vendor = Citrix
  Product = Web Logging
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy:HH:mm:ss z"
  Conditions = [ """ SSLVPN HTTPREQUEST """, """ User """, """ : SSO is """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """((\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+)?<\d+>)?\s+({time}\d+\/\d+\/\d+:\d+:\d+:\d+\s+\w+)\s+({dest_host}[\w\-.]+).+?({user}[^\s@]+)@({src_ip}[A-Fa-f:\d.]+).+?({web_domain}[^\s]+)\s+User\s+({=user}[^\s:]+).+?Vserver\s+({dest_ip}[A-Fa-f:\d.]+?):({dest_port}\d+).+?SSO is (ON|OFF)\s*:\s*({method}\S+)\s+({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?\s+""",
    """({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|media|goog|ae|corp))+)\s+User"""
  ]
}
```