package domain.utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

public class JsonManipulator {

	public static void writeJsonToFile(JsonObject jsonObject, String filePath) throws Exception {
        try (FileWriter fileWriter = new FileWriter(filePath)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(jsonObject, fileWriter);
        }
    }

    public static JsonObject readJsonFromFile(String filePath) throws FileNotFoundException {
        FileReader fileReader = new FileReader(filePath);
        return new Gson().fromJson(fileReader, JsonObject.class);
    }

    public static void createTextFile(String path, String fileName, String content) {
        File file = new File(path, fileName);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);

        } catch (IOException e) {
            System.err.println("An error occurred while creating the file: " + e.getMessage());
        }
    }
    
    public static JsonObject getRootJson(String filename) {
    	
    	JsonObject root = null;
        
    	try (FileReader fileReader = new FileReader(filename)) {
            Gson gson = new Gson();
            root = gson.fromJson(fileReader, JsonObject.class);
        } catch (Exception e) {
        	e.printStackTrace();
        }
        
        return root;
    }
	
}
