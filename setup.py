from distutils.core import setup

setup(
        name = 'https-info',
        author = 'Pawel Krawczyk',
        author_email = 'pawel.krawczyk@hush.com',
        url = '',
        version = '1.0',
        packages = ['https-info',],
        description = 'Query SSL servers for basic information such as certificates and HTTP headers',
        license = 'GNU General Public License v3 or later (GPLv3+)',
        classifiers = [
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
            'Topic :: Security :: Cryptography',
            'Programming Language :: Python',
            'Topic :: Software Development :: Libraries',
            ],
        requires = 'OpenSSL',
        )
