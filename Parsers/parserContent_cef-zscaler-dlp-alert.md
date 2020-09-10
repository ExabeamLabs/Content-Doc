#### Parser Content
```Java
{
Name = cef-zscaler-dlp-alert
  Vendor = Zscaler
  Product = NSS
  Lms = ArcSight
  DataType = "dlp-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Zscaler|NSSWeblog|""", """Blocked""", """act=""", """ZscalerNSSWeblogDLPDictionaries""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\srt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+) CEF:""",
    """\sdvchost=({host}[\w\-.]+)\s*(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """\sdst=({dest_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """([^\|]*\|){5}({action}[^\|]+)""",
    """(\s|\|)act=({action}.+?)\s*(\w+=|$)""",
    """\ssuser=(?![^\s]+@[^\s]+)({user}.+?)\s*(\w+=|$)""",
    """\ssuser=({user_email}({user}[^\s@]+)@[^\s]+)\s*(\w+=|$)""",
    """\sapp=({protocol}.+?)\s*(\w+=|$)""",
    """\scs4=(None|({ransomware_name}.+?))\s*(\w+=|$)""",
    """\srequest=({full_url}.+?)\s*(\w+=|$)""",
    """\srequest=(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s]+)(\?\S+)?\s+(\w+=|$)""",
    """\srequest=(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?[^\s]+)""",
    """\srequest=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)""",
    """\srequest=[^\s?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s\w+=|\/))[^\s:\/]+)""",
    """\srequestMethod=(NA|({method}.+?))\s*(\w+=|$)""",
    """\srequestClientApplication=([uU]nknown|({user_agent}.+?))\s*(\w+=|$)""",
    """\srequestClientApplication=([uU]nknown|({browser}.+?))\s*(\w+=|$)""",
    """\sout=({bytes_in}\d+)""",
    """\sin=({bytes_out}\d+)""",
    """\s(ad\.)?ZscalerNSSWeblogURLClass=({category}.+?)\s*(\w+=|$)""",
    """\sfileType=(None|({mime}.+?))\s*(\w+=|$)""",
    """\soutcome=({result_code}\d+)""",
    """\sreason=({alert_name}.+?)\s*(\w+=|$)""",
    """\srequestClientApplication=(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?([uU]nknown|({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)))""",
  ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "protocol->dlpProtocol", "src_ip->dlpDeviceName", "outcome->dlpActionTaken"]
      NameTemplate = """ZScaler DLP Alert: ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```