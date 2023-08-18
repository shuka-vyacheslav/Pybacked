import subprocess
import platform


def install_zbar_dependency():
    system = platform.system()
    if system == "Linux":
        package_managers = ["dnf", "yum", "pacman", "zypper"]
        installed_manager = None
        for manager in package_managers:
            try:
                subprocess.run(
                    ["which", manager],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                installed_manager = manager
                break
            except subprocess.CalledProcessError:
                pass
        if installed_manager:
            subprocess.run(["sudo", installed_manager, "install", "libzbar0"])
        else:
            print(
                "No supported package manager found. Please install zbar manually (https://github.com/sbrown89/libzbar)."
            )
    elif system == "Darwin":
        subprocess.run(["brew", "install", "zbar"])
    elif system == "Windows":
        pass
    else:
        print(
            "Unsupported operating system. Please install zbar manually (https://github.com/sbrown89/libzbar)."
        )


def main():
    install_zbar_dependency()


if __name__ == "__main__":
    main()
