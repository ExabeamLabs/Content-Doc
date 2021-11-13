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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wtk_date_field=({time}[^,"]{1,2000})""",
    """\Wtk_server_ip=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wtk_server=({host}[\w\-.]{1,2000})""",
    """\Wtk_username=(({user_fullname}\w+(\s{1,100}\w+)+)|({user}\w+)|({src_ip}[a-fA-F\d.:]{1,2000})),""",
    """\Wtk_client_ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wtk_url=(-|({full_url}(({protocol}[^:\\\/\s,]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,]{1,2000})(:\d{1,100})?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s,]{0,2000})?))""",
    """\Wtk_protocol=({protocol}[^,"]{1,2000})""",
    """\Wtk_category=(0|({categories}({category}[^,";\/]{1,2000})[^,]{0,2000}))""",
    """\Wtk_file_name=({uri_path}[^,"]{1,2000})""",
    """\Wtk_operation=({method}[^,"]{1,2000})""",
    """\Wtk_mime_content=(none|({mime}[^,"]{1,2000}))""",
    """\Wtk_scan_type=({scan_type}[^,"]{1,2000})""",
    """\Wtk_rule_name=({rule}[^,"]{1,2000})""",
    """\Wtk_filter_action=({action}[^,"\s]{1,2000})""",
    """\[({outcome}EVT_\w+)\s{0,100}\|""",
  ]


}
```