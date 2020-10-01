#### Parser Content
```Java
{
Name = cef-cyberark-account-switch
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """act=Retrieve password""", """Safe""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}\S+?)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}\S+?)(\s+\w+=|\s*$)""",
    """\sshost=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))(\s+\w+=|\s*$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=(({domain}[^\\=]+?)(\\)+)?({user}.+?)\s+\w+=""",
    """\sfname=([^=]+?\-)?({account}[^\s-]+?)(\\+(=.*?|({admin_id}[^\\\s]+)))?\s+\w+=""",
    """\sduser=([^\\=]+\\+)?({account}[^=]+?)\s+\w+=""",
    """cs2=(|({safe_value}[^=]+?))\s+\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^=]+?)(\s+\w+=|\s*$)""",
  ]
}
```