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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\S+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}\S+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=(({domain}[^\\=]+?)(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """\sfname=([^=]+?\-)?({account}[^\s-]+?)(\\+(=.*?|({admin_id}[^\\\s]+)))?\s{1,100}\w+=""",
    """\sduser=([^\\=]+\\+)?({account}[^=]+?)\s{1,100}\w+=""",
    """cs2=(|({safe_value}[^=]+?))\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```