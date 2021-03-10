#### Parser Content
```Java
{
Name = bro-ssh
  Vendor = Bro
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
```