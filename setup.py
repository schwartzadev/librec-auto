import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="librec-auto",
    version="0.1.27",
    scripts=['core\__main__.py'] ,
    author="Masoud Mansoury and Robin Burke",
    author_email="masoodmansoury@gmail.com",
    description="The librec-auto project aims to automate recommender system experimens using LibRec.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/that-recsys-lab/librec-auto",
    packages=setuptools.find_packages(),
    include_package_data=True,
    install_requires=[
        'matplotlib',
        'pandas',
        'numpy',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
