#### Parser Content
```Java
{
Name = s-sophos-network-connection
  Vendor = Sophos
  Product = Sophos XG Firewall
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """device="SFW"""", """log_component="Firewall Rule"""]
  Fields = [
    """date=({time}\d{4}-\d\d-\d\d\stime=\d\d:\d\d:\d\d)""",
    """\sdevice_name="({host}\S+)?"\s""",
    """\sdevice_id=({device_id}\S*)?\s""",
    """\slog_id=({log_id}\S+)?\s""",
    """\slog_type="({log_type}\S+)?"\s""",
    """\slog_subtype="({subtype}\S+)?"\s""",
    """\sstatus="({action}\S+)?"\s""",
    """\spriority=({priority}\S+)?\s""",
    """\sduration=({duration}\d{1,100})?\s""",
    """\sfw_rule_id=({rule_id}\d{1,100})?\s""",
    """\spolicy_type=({policy}\S+)?\s""",
    """\suser_name="(({user}[^"@]{1,2000}?)|({user_email}[^"@]{1,2000}@[^"]{1,2000}))?"\s.*?\s""",
    """\sin_interface="({src_interface}\S+)?"\s""",
    """\sout_interface="({dest_interface}\S+)?"\s""",
    """\ssrc_mac=({src_mac}\S+)?\s""",
    """\ssrc_ip=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s""",
    """\ssrc_country_code=({src_country_code}\S+)?\s""",
    """\sdst_ip=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s""",
    """\sdst_country_code=({dest_county_code}\S+)?\s""",
    """\sprotocol="({protocol}\S+)?"\s""",
    """\ssrc_port=({src_port}\d{1,100})?\s""",
    """\sdst_port=({dest_port}\d{1,100})?\s""",
    """\stran_src_ip=({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s""",
    """\stran_src_port=({src_translated_port}\d{1,100})?\s""",
    """\stran_dst_ip=({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s""",
    """\stran_dst_port=({dest_translated_port}\d{1,100})?\s""",
  ]
  DupFields = [ "action->outcome" ]
}
```