import subprocess
import sys


def install(name):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', name])


def main():
    my_packages = ['secure-smtplib', 'pyAesCrypt', 'pyaes', 'pbkdf2', 'pillow', 'cryptography', 'update_check',
                   'pyperclip', 'tkscrolledframe', 'mysql-connector-python', 'tkhtmlview']
    installed_pr = []
    for package in my_packages:
        install(package)
        print('\n')


if __name__ == '__main__':
    main()
