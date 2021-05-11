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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wact=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wext_detection=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({process}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """timestamp":\s{0,100}({time}\d{1,100})""",
    """detection":\s{0,100}"({alert_name}[^"]+)""",
    """event_type":\s{0,100}"({alert_type}[^"]+)""",
    """\Wsuser=((?i)(anonymous|system)|({user}[^\\\s@]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=((?i)(anonymous|system)|({user_email}[^@\s]+?@[^@\s\.=]+?\.[^@\s\.=]+?)|({user}[^@\s=]+?@(NT AUTHORITY|({domain}[^@\s\.=]+?))))(\s{1,100}\w+=|\s{0,100}$)""",
    """user":\s{0,100}"((?i)(anonymous|system)|({user}[^"@\s]+))"""",
    """user"{1,20}:\s{0,100}"{1,20}((?i)(anonymous|system)|({user_email}[^@]+@[^@"]+\.[^"]+)|({user}[^@]+)@(NT AUTHORITY|({domain}[^"]+)))""",
    """hostname":\s{0,100}"({src_host}[^"]+)""",
    """file_path":\s{0,100}"(\\+\?\\+)?({file_path}[^"]+)""",
    """external_ip":\s{0,100}"({dest_ip}[^"]+)""",
    """"network_addresses":.+?"ip":\s{0,100}"({src_ip}[^"]+)""",
    """"trajectory":\s{0,100}"({additional_info}[^"]+)""",
    """,\s{0,100}"disposition":\s{0,100}"(Unknown|({alert_severity}[^"\s]+))"""",
    """"file":\{([^\{\}]*?\{([^\{\}]*?\{([^\{\}]*?\{[^\{\}]*?\})*[^\{\}]*?\})*[^\{\}]*?\})*[^\{\}]*?"disposition":"(Unknown|({alert_severity}[^"\s]+))"""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"file_name":\s{0,100}"({file_name}[^"]+)"([^\{\}]*?\{([^\{\}]*?\{[^\{\}]*?\})*[^\{\}]*?\})*[^\{\}]*?"disposition":""",
    """,\s{0,100}"disposition":.+?file_name":\s{0,100}"({file_name}[^"]+)""",
    """"sha256":\s{0,100}"({sha256}[^"]+)""",
    """"sha1":\s{0,100}"({sha1}[^"]+)""",
    """"md5":\s{0,100}"({md5}[^"]+)""",
    """"file_name":\s{0,100}"({file_name}[^"]+)[^\}]+?"disposition"""",
    """\s{0,100}"disposition":[^\{]+?file_name":\s{0,100}"({file_name}[^"]+)""",
    """,\s{0,100}"disposition":.+?md5":\s{0,100}"({md5}[^"]+)""",
    """\sdestinationServiceName=({product_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"ip":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """src=({src_ip}[\da-fA-F.:]+)""",
    """"mac":\s{0,100}"({mac}[^"]+)""",
    """\Woutcome=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"connector_guid":"({connector_guid}[^"]+)""",
  ]

```