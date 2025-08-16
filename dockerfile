#tell docker to use node.js
FROM node:23-alpine

#to set the working directory 
WORKDIR /app

#copy the files from local project
COPY package*.json .

#download all the packages we need
RUN npm install

#copy the rest of the code
COPY . . 

# expose the port the app runs on
EXPOSE 3006

#difine the command to run the app
CMD [ "node", "index.js"]
