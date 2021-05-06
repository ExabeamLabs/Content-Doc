#### Parser Content
```Java
{
Name = s-cisco-amp-alert-11
  Conditions = [ """"event_type"""", """"Policy Update Failure"""", """"trajectory":""", """"timestamp_nanoseconds":""" ]
  Fields=${CiscoParsersTemplates.s-cisco-amp-alert.Fields}[
    """file_name":"({process_name}[^\.]+\.exe)"""
  ]
}
s-cisco-amp-alert = {
  Vendor = Cisco
  Product = Cisco Secure Endpoint
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wact=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\Wext_detection=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({process}.+?))(\s+\w+=|\s*$)""",
    """\Woutcome=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """timestamp":\s*({time}\d+)""",
    """detection":\s*"({alert_name}[^"]+)""",
    """event_type":\s*"({alert_type}[^"]+)""",
    """\Wsuser=((?i)(anonymous|system)|({user}[^\\\s@]+?))(\s+\w+=|\s*$)""",
    """\Wsuser=((?i)(anonymous|system)|({user_email}[^@\s]+?@[^@\s\.=]+?\.[^@\s\.=]+?)|({user}[^@\s=]+?@(NT AUTHORITY|({domain}[^@\s\.=]+?))))(\s+\w+=|\s*$)""",
    """user":\s*"((?i)(anonymous|system)|({user}[^"@\s]+))"""",
    """user"+:\s*"+((?i)(anonymous|system)|({user_email}[^@]+@[^@"]+\.[^"]+)|({user}[^@]+)@(NT AUTHORITY|({domain}[^"]+)))""",
    """hostname":\s*"({src_host}[^"]+)""",
    """file_path":\s*"(\\+\?\\+)?({file_path}[^"]+)""",
    """external_ip":\s*"({dest_ip}[^"]+)""",
    """"network_addresses":.+?"ip":\s*"({src_ip}[^"]+)""",
    """"trajectory":\s*"({additional_info}[^"]+)""",
    """,\s*"disposition":\s*"(Unknown|({alert_severity}[^"\s]+))"""",
    """"file":\{([^\{\}]*?\{([^\{\}]*?\{([^\{\}]*?\{[^\{\}]*?\})*[^\{\}]*?\})*[^\{\}]*?\})*[^\{\}]*?"disposition":"(Unknown|({alert_severity}[^"\s]+))"""",
    """"severity":\s*"({alert_severity}[^"]+)""",
    """"file_name":\s*"({file_name}[^"]+)"([^\{\}]*?\{([^\{\}]*?\{[^\{\}]*?\})*[^\{\}]*?\})*[^\{\}]*?"disposition":""",
    """,\s*"disposition":.+?file_name":\s*"({file_name}[^"]+)""",
    """"sha256":\s*"({sha256}[^"]+)""",
    """"sha1":\s*"({sha1}[^"]+)""",
    """"md5":\s*"({md5}[^"]+)""",
    """"file_name":\s*"({file_name}[^"]+)[^\}]+?"disposition"""",
    """\s*"disposition":[^\{]+?file_name":\s*"({file_name}[^"]+)""",
    """,\s*"disposition":.+?md5":\s*"({md5}[^"]+)""",
    """\sdestinationServiceName=({product_name}.+?)(\s+\w+=|\s*$)""",
    """"ip":\s*"({src_ip}[a-fA-F\d.:]+)""",
    """src=({src_ip}[\da-fA-F.:]+)""",
    """"mac":\s*"({mac}[^"]+)""",
    """\Woutcome=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """"connector_guid":"({connector_guid}[^"]+)""",
  ]

```