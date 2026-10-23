import paramiko


def open_ssh(host, port, username, password=None, key_file=None) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # TODO: bản thật phải dùng RejectPolicy + known_hosts. AutoAdd chỉ để dev cho nhanh.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password,
                   key_filename=key_file, timeout=20)
    return client
