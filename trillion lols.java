import org.yaml.snakeyaml.Yaml;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TrillionLols {
    public static void main(String[] args) {
        List<String> trillionLols = new ArrayList<>();
        for (int i = 0; i < 1000000000; i++) {
            trillionLols.add("LOL");
        }

        Yaml yaml = new Yaml();
        try {
            FileWriter writer = new FileWriter("trillion_lols.yaml");
            yaml.dump(trillionLols, writer);
            writer.close();
            System.out.println("Done!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}