import setuptools

setuptools.setup(
    name="jmpscare_col",
    version="0.0.2",
    author="@pr0me",
    author_email="author@example.com",
    description="Package for execution trace collection via unicornafl, for the use with JMPscare.",
    long_description=None,
    long_description_content_type="text/markdown",
    url="https://github.com/fgsect/JMPscare/collection/python",
    packages=["jmpscare_col"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
