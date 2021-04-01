#### Parser Content
```Java
{
Name = zscaler-proxy
    Vendor = Zscaler
    Product = Zscaler Internet Access
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|ESM|""","""ZSCALER"""]
    Fields = [
      """\srt=({time}\d+)""",
      """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\ssuser=(?![^\s]+@[^\s]+)({user}[^\s]+)""",
      """\ssuser=(?=[^\s]+@[^\s]+)({user_email}({user}[^\s@]+)@[^\s]+)""",
      """\ssuser=({user}[^\s@]+)@""",
      """\sduser=({browser}.+?)\s+(\(|\w+=)""",
      """\sact=({action}.+?)\s+\w+=""",
      """\snitroResponse_Code=({result_code}\d+)""",
      """\snitroURL=({full_url}\S+)""",
      """\snitroURL_Category=({category}.+?)\s+(-|\w+=)""",
      """\snitroURL=(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s]+)""",
      """\snitroURL=(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?[^\s]+)""",
      """\snitroURL=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)""",
      """\snitroURL=[^\s?=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s\w+=|\/))[^\s:\/]+)""" ]
  }
```