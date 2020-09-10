#### Parser Content
```Java
{
Name = thycotic-account-switch
  Vendor = Thycotic Secret Server
  Product = Thycotic Secret Server
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [  """|Thycotic Software|""","""|SECRET - CHECKOUT|""","""Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]+) CEF:""",
    """\srt=({time}\d+)""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\ssuser=(({domain}[^\\=]+)(\\)+)?({user}.+?)\s+\w+=""",
    """\sfname=(({account_domain}[^\\=]+)(\\)+)?({account}.+?)\s+\w+=""",
    """cs3=({safe_value}.+?)\s+(\w+=|$)"""
  ]
	DupFields=["host->dest_host"]
}
```