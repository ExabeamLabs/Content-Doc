#### Parser Content
```Java
{
Name = squid-web-activity-2
  Vendor = Squid
  Product = Squid
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """[EVT_""", """,tk_url=""", """,tk_protocol=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wtk_date_field=({time}[^,"]+)""",
    """\Wtk_server_ip=({host}[A-Fa-f:\d.]+)""",
    """\Wtk_server=({host}[\w\-.]+)""",
    """\Wtk_username=(({user_fullname}\w+(\s+\w+)+)|({user}\w+)|({src_ip}[a-fA-F\d.:]+)),""",
    """\Wtk_client_ip=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wtk_url=(-|({full_url}(({protocol}[^:\\\/\s,]+):[\\\/]+)?({web_domain}[^\\\/\s:,]+)(:\d+)?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s,]*)?))""",
    """\Wtk_protocol=({protocol}[^,"]+)""",
    """\Wtk_category=(0|({categories}({category}[^,";\/]+)[^,]*))""",
    """\Wtk_file_name=({uri_path}[^,"]+)""",
    """\Wtk_operation=({method}[^,"]+)""",
    """\Wtk_mime_content=(none|({mime}[^,"]+))""",
    """\Wtk_scan_type=({scan_type}[^,"]+)""",
    """\Wtk_rule_name=({rule}[^,"]+)""",
    """\Wtk_filter_action=({action}[^,"\s]+)""",
    """\Wtk_url=[^,\s\?]*?({top_domain}[^\\\/:\s.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """\[({outcome}EVT_\w+)\s*\|""",
  ]
}
```