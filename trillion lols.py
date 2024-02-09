import yaml

trillion_lols = ["LOL"] * 1000000000

yaml_data = {"lols": trillion_lols}
yaml.dump(yaml_data, open("trillion_lols.yaml", "w"))
print("Done!")