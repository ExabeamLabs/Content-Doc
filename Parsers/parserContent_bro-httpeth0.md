#### Parser Content
```Java
{
Name = bro-httpeth0
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ "/http_eth0.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|([^\t]+))\t(?:-|({method}[^\t]+))\t(?:-|([^\t]+))\t([^\t]+)\t(?:-|({referrer}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({user_agent}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({result_code}[^\t]+))\t(?:-|({status_msg}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|(\(empty\))|({tags}[^\t]+))\t(?:-|({user}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({proxied}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({orig_filenames}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({mime}[^\t]+?))\s*$""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|([^\t]+))\t(?:-|({method}[^\t]+))\t(?:-|([^\t]+))\t([^\t]+)\t(?:-|({referrer}[^\t]+))\t(?:-|({user_agent}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({result_code}[^\t]+))\t(?:-|({status_msg}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({orig_filenames}[^\t]+))\t(?:-|(\(empty\))|({tags}[^\t]+))\t(?:-|({user}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({proxied}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({mime}[^\t]+?))\s*$""",
    """\d{10}\.\d{6}\t([^\t]+\t){7}(?:-|(?!(\d{1,3}\.){3}\d{1,3})({web_domain}.+?))\s*\t([^\t]+\t){16}(?:-|({mime}[^\t]+))\t""",
    """\d{10}\.\d{6}\t([^\t]+\t){7}[^\t]*?({top_domain}[^\t.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """\d{10}\.\d{6}\t([^\t]+\t){8}(?:-|({uri_path}[^\t\?]+)(\?({uri_query}[^\t]+))?)""",
    """\d{10}\.\d{6}\t([^\t]+\t){11}[^\t]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\d{10}\.\d{6}\t([^\t]+\t){11}[^\t]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """({protocol}http)"""
  ]
}
{
  Name = bro-ssh
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "epoch_sec"
  Conditions = [ "/ssh.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({version}[^\t]+))\t(?:-|({outcome}[^\t]+))\t(?:-|({auth_attempts}[^\t]+))\t(?:-|({direction}[^\t]+))\t(?:-|({client_ssh_version}[^\t]+))\t(?:-|({server_ssh_version}[^\t]+))\t(?:-|({cipher}[^\t]+))\t(?:-|({mac_alg}[^\t]+))\t(?:-|(none)|({compression_alg}[^\t]+))\t(?:-|({kex_alg}[^\t]+))\t(?:-|({host_key_alg}[^\t]+))\t(?:-|({host_key}[^\t]+))\t(?:-|({remote_location_country_code}[^\t]+))\t(?:-|({remote_location_region}[^\t]+))\t(?:-|({remote_location_city}[^\t]+))\t(?:-|({remote_location_latitude}[^\t]+))\t(?:-|({remote_location_longitude}[^\t]+?))\s*$""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({version}[^\t]+))\t(?:-|({outcome}[^\t]+))\t(?:-|({direction}[^\t]+))\t(?:-|({client_ssh_version}[^\t]+))\t(?:-|({server_ssh_version}[^\t]+))\t(?:-|({cipher}[^\t]+))\t(?:-|({mac_alg}[^\t]+))\t(?:-|(none)|({compression_alg}[^\t]+))\t(?:-|({kex_alg}[^\t]+))\t(?:-|({host_key_alg}[^\t]+))\t(?:-|({host_key}[^\t]+))\t(?:-|({remote_location_country_code}[^\t]+))\t(?:-|({remote_location_region}[^\t]+))\t(?:-|({remote_location_city}[^\t]+))\t(?:-|({remote_location_latitude}[^\t]+))\t(?:-|({remote_location_longitude}[^\t]+?))\s*$"""
  ]
}
{
  Name = bro-share-access-2
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "epoch_sec"
  Conditions = [ "\tSMB::FILE_OPEN\t", "\t445\t" ]
  Fields = [
     """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({file_id}[^\t]+))\t(?:-|({event_name}[^\t]+))\t(?:-|({share_path}[^\t]+))\t(?:-|({file_name}[^\t]+))\t(?:-|({bytes}[^\t]+))\t(?:-|({src_file_name}[^\t]+))\t(?:-|({times_modified}[^\t]+))\t(?:-|({time_accessed}[^\t]+))\t(?:-|({time_created}[^\t]+))\t(?:-|({time_changed}[^\t]+?))\s*$""",
     """SMB::({accesses}FILE_OPEN)""",
     """\d{10}\.\d{6}\t([^\t]+\t){8}({file_path}({file_parent}[^\t]*?(\\u005c|[\\\/])*)({file_name}[^\t\\\/]+?(\.({file_ext}[^\t\\\/\.]+))?))\t""",
     """({protocol}SMB)"""
    ]
}
```