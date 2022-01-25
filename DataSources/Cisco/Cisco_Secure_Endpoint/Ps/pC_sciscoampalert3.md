#### Parser Content
```Java
{
Name = s-cisco-amp-alert-3
  Conditions = [ """"event_type"""", """Threat Detected""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]{1,2000}\.exe)"""
  ]

s-cisco-amp-alert = {
  Vendor = Cisco
  Product = Cisco Secure Endpoint
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wact=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """dpriv=({alert_name}[^=]{1,2000}?)\s\w{1,2000}=""",
    """\Wext_detection=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({process}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """timestamp":\s{0,100}({time}\d{1,100})""",
    """detection":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """event_type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """\Wsuser=((?i)(anonymous|system)|({user}[^\\\s@]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=((?i)(anonymous|system)|({user_email}[^@\s]{1,2000}?@[^@\s\.=]{1,2000}?\.[^@\s\.=]{1,2000}?)|({user}[^@\s=]{1,2000}?@(NT AUTHORITY|({domain}[^@\s\.=]{1,2000}?))))(\s{1,100}\w+=|\s{0,100}$)""",
    """user":\s{0,100}"((?i)(anonymous|system)|({user}[^"@\s]{1,2000}))"""",
    """user"{1,20}:\s{0,100}"{1,20}((?i)(anonymous|system)|({user_email}[^@]{1,2000}@[^@"]{1,2000}\.[^"]{1,2000})|({user}[^@]{1,2000})@(NT AUTHORITY|({domain}[^"]{1,2000})))""",
    """hostname":\s{0,100}"({src_host}[^"]{1,2000})""",
    """file_path":\s{0,100}"(\\+\?\\+)?({file_path}[^"]{1,2000})""",
    """external_ip":\s{0,100}"({dest_ip}[^"]{1,2000})""",
    """"network_addresses":.+?"ip":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"trajectory":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """,\s{0,100}"disposition":\s{0,100}"(Unknown|({alert_severity}[^"\s]{1,2000}))"""",
    """"file":\{([^\{\}]{0,2000}?\{([^\{\}]{0,2000}?\{([^\{\}]{0,2000}?\{[^\{\}]{0,2000}?\})*[^\{\}]{0,2000}?\})*[^\{\}]{0,2000}?\})*[^\{\}]{0,2000}?"disposition":"(Unknown|({alert_severity}[^"\s]{1,2000}))"""",
    """CEF:([^\|]{1,2000}\|){6}({alert_severity}[^\|]{1,2000})\|""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"file_name":\s{0,100}"({file_name}[^"]{1,2000})"([^\{\}]{0,2000}?\{([^\{\}]{0,2000}?\{[^\{\}]{0,2000}?\})*[^\{\}]{0,2000}?\})*[^\{\}]{0,2000}?"disposition":""",
    """,\s{0,100}"disposition":.+?file_name":\s{0,100}"({file_name}[^"]{1,2000})""",
    """"sha256":\s{0,100}"({sha256}[^"]{1,2000})""",
    """"sha1":\s{0,100}"({sha1}[^"]{1,2000})""",
    """"md5":\s{0,100}"({md5}[^"]{1,2000})""",
    """"file_name":\s{0,100}"({file_name}[^"]{1,2000})[^\}]{1,2000}?"disposition"""",
    """\s{0,100}"disposition":[^\{]{1,2000}?file_name":\s{0,100}"({file_name}[^"]{1,2000})""",
    """,\s{0,100}"disposition":.+?md5":\s{0,100}"({md5}[^"]{1,2000})""",
    """\sdestinationServiceName =({product_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """src=({src_ip}[\da-fA-F.:]{1,2000})""",
    """"mac":\s{0,100}"({mac}[^"]{1,2000})""",
    """\Woutcome=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"connector_guid":"({connector_guid}[^"]{1,2000})""",
  ]
  DupFields = [ "file_path->malware_url", "alert_type->category" ]
    SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_type->description", "alert_severity->sourceSeverity", "additional_info->sourceUrl", "file_path->malwareAttackerFile", "src_host->malwareVictimHost", "alert_name->malwareName"]
    NameTemplate = """Cisco AMP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]},
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address"]},
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]},
      {EntityType="file", Name ="file_name", Fields=["file_name->file_name"]}
    
}
```