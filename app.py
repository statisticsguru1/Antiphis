# import feature extractor
from get__features import *
import pandas as pd
import tensorflow as tf
import tensorflow_addons
import numpy as np
import pickle
import json
import shiny
from shiny import App, render, ui,reactive, ui,run_app
from htmltools import TagList, div

# valid tags and suspicious function

vd = get_valid_html_tags()
sf = get_suspicious_functions()

# load column names of the training data and model accuracy
with open('train_columns.json', 'r') as f:
    train_dummies_columns = json.load(f)

with open('overall.json', 'r') as f:
    accuracies = json.load(f)
    
# load models
# svm
with open('svcmodel.pkl', 'rb') as f:
    svc = pickle.load(f)
    
# boosted
with open('boosted.pkl', 'rb') as f:
    boosted = pickle.load(f)
    
# DT
with open('DT.pkl', 'rb') as f:
    DT= pickle.load(f)
# KNN
with open('KNNmod.pkl', 'rb') as f:
    KNN= pickle.load(f)

# RF
with open('RF.pkl', 'rb') as f:
    RF= pickle.load(f)
    
#ANN
ANN=tf.keras.models.load_model('model.h5')

# changing labels to cat

def to_categorical(label):
  if label==0:
    x="Legitimate"
  else:
    x="phishing"
  return x

app_ui = ui.page_fluid(
            ui.tags.style(
        """
    body {
      background-color: #F5F5F5;
    }
    h3, h4 {
      color: #2F408D;
    }
    #Go{
    background-color:#2F408D;
      color: white;
    }
        """
    ),
    ui.navset_tab(
       ui.nav("URL Check",
          ui.h3(""),
          ui.tags.br(),
          ui.tags.br(),
          ui.tags.br(),
          ui.tags.br(),
          ui.row(ui.column(3,),
                 ui.column(6,
                   ui.input_text(id="url",label="",placeholder="Enter url",value="http://example.com",width='700px'),),
                 ui.column(3,)),
          ui.row(ui.column(4,),
                 ui.column(4,
                           ui.input_action_button(id="Go",label="check",width="200px"),),
                 ui.column(4,))),
       ui.nav("Extracted Features",
          ui.row(
             ui.column(4,
                        ui.output_ui("txt_title30"),
                        ui.output_text_verbatim("lexical_feats"),),
             ui.column(4,
                        ui.output_ui("txt_title31"),
                        ui.output_text_verbatim("content_feats"),),
             ui.column(4,
                        ui.output_ui("txt_title32"),
                        ui.output_text_verbatim("host_feats"),),
          ),
          ui.row(
             ui.column(12,
                        ui.output_ui("txt_title33"),
                        ui.output_text_verbatim("final_result"),),
             )
             )))

def server(input, output, session):
    @reactive.Calc
    @reactive.event(input.Go)
    def extract_features():
        url = input.url()
        # initialize
        print("Initializing LexicalURLFeature extractor")
        lexicalinst=LexicalURLFeature(url)
        print("Initializing ContentFeature extractor")
        contentinst=ContentFeatures(url,vd=vd,sf=sf)
        print("Initializing HostFeature extractor")
        hostinst=HostFeatures(url)
        # get features
        print("Getting features from feature extractor classes")
        lexical=lexicalinst.run()
        content=contentinst.run()
        host=hostinst.run()
        print("Data preparation complete")
        return [lexical,content,host]
    
    
    @reactive.Calc
    @reactive.event(input.Go)
    def combined_features():
      features=extract_features()
      lexical=features[0]
      content=features[1]
      host=features[2]
      dat=lexical.copy()
      dat.update(content)
      dat.update(host)
      dat=pd.DataFrame([dat])
      dat=dat.drop(columns=['host','url','first_seen','last_seen'])
      # add those missing dummies
      for column in train_dummies_columns:
        if column not in dat.columns:
          dat[column] = 0
      # remove any extra category not seen during training
      dat=dat[train_dummies_columns] 
      print("Combining features complete")
      return dat
    
    @reactive.Calc
    def Ann_pred(): 
      dat=combined_features()
      ANNpred=np.argmax(ANN.predict(np.asarray(dat).astype(np.int)),axis=1)
      print("Ann prediction complete")
      return to_categorical(ANNpred)
    
    @reactive.Calc
    def svc_pred(): 
      dat=combined_features()
      svcpred=svc.predict(dat)
      print("SVC prediction complete")
      return to_categorical(svcpred)
    
    @reactive.Calc
    def boosted_pred(): 
      dat=combined_features()
      boostedpred=boosted.predict(dat)
      print("boosted prediction complete")
      return to_categorical(boostedpred)
    
    @reactive.Calc
    def DT_pred(): 
      dat=combined_features()
      DTpred=DT.predict(dat)
      print("DT prediction complete")
      return to_categorical(DTpred)

    @reactive.Calc
    def KNN_pred(): 
      dat=combined_features()
      KNNpred=KNN.predict(dat)
      print("KNN prediction complete")
      return to_categorical(KNNpred)

    @reactive.Calc
    def RF_pred(): 
      dat=combined_features()
      RFpred=RF.predict(dat)
      print("RF prediction complete")
      return to_categorical(RFpred)

    @output
    @render.ui
    @reactive.event(input.Go)
    def txt_title1():
        return ui.tags.h4("Prediction model's results")
      
    @output
    @render.text
    @reactive.event(input.Go)
    def svc_out():
        pred=svc_pred()
        acc=round(100*accuracies['SVM'],2)
        return f"Support Vector Machine({acc}%): {pred}"

    @output
    @render.text
    @reactive.event(input.Go)
    def boosted_out():
        pred=boosted_pred()
        acc=round(100*accuracies['Boosted'],2)
        return f"Boosted Decison tree({acc}%): {pred}"

    @output
    @render.text
    @reactive.event(input.Go)
    def DT_out():
        pred=DT_pred()
        acc=round(100*accuracies['DT'],2)
        return f"Decison tree({acc}%): {pred}"
      
    @output
    @render.text
    @reactive.event(input.Go)
    def KNN_out():
        pred=KNN_pred()
        acc=round(100*accuracies['KNN'],2)
        return f"K nearest Neighbour({acc}%): {pred}"

    @output
    @render.text
    @reactive.event(input.Go)
    def RF_out():
        pred=RF_pred()
        acc=round(100*accuracies['RF'],2)
        return f"Random Forest({acc}%): {pred}"
      
    @output
    @render.ui
    @reactive.event(input.Go)
    def txt_title2():
        return ui.tags.h3("Best model's results")
      
    @output
    @render.text
    @reactive.event(input.Go)
    def ANN_out():
        pred=Ann_pred()
        acc=round(100*accuracies['ANN'],2)
        return f"Artificial Neural Network ({acc}%): {pred}"
      
    @reactive.Calc
    @reactive.event(input.Go)
    def combined_outs():
      return {'Support vector machine':svc_pred(),
              'Decision Tree':DT_pred(),
              'Boosted Decision trees':boosted_pred(),
              'Random Forest': RF_pred(),
              'K nearest Neigbour':KNN_pred(),
              'Artificial Neural Network':Ann_pred()}

    @output
    @render.ui
    @reactive.event(combined_outs)
    def txt_title30():
        return ui.tags.h3("Lexical features")

    @output
    @render.ui
    @reactive.event(combined_outs)
    def txt_title31():
        return ui.tags.h3("Content features")

    @output
    @render.ui
    @reactive.event(combined_outs)
    def txt_title32():
        return ui.tags.h3("Host features") 

    @output
    @render.ui
    @reactive.event(combined_outs)
    def txt_title33():
        return ui.tags.h3("Predicted status")  

    @output
    @render.text
    @reactive.event(combined_outs)
    def lexical_feats():
        features=extract_features()
        lexical=features[0]
        formatted_pairs = [f"{key:<15}: {value}" for key, value in lexical.items()]
        return "\n".join(formatted_pairs)
    
    @output
    @render.text
    @reactive.event(combined_outs)
    def content_feats():
        features=extract_features()
        content=features[1]
        formatted_pairs = [f"{key:<15}: {value}" for key, value in content.items()]
        return "\n".join(formatted_pairs)

    @output
    @render.text
    @reactive.event(combined_outs)
    def host_feats():
        features=extract_features()
        host=features[2]
        formatted_pairs = [f"{key:<15}: {value}" for key, value in host.items()]
        return "\n".join(formatted_pairs)

    @output
    @render.text
    @reactive.event(combined_outs)
    def final_result():
        res=combined_outs()
        formatted_pairs = [f"{key}: {value}" for key, value in res.items()]
        rows = [formatted_pairs[i:i+5] for i in range(0, len(formatted_pairs), 5)]
        return "\n".join("    ".join(row) for row in rows)


    @reactive.Effect
    @reactive.event(combined_outs)
    def _():
      m=ui.modal(
        ui.output_ui("txt_title1"),
        ui.output_text("svc_out"),
        ui.output_text("DT_out"),
        ui.output_text("ANN_out"),
        ui.output_text("RF_out"),
        ui.output_text("KNN_out"),
        ui.output_ui("txt_title2"),
        ui.output_text("boosted_out"),
        easy_close=True,
        footer=ui.TagList(
          ui.modal_button("Cancel"),
          ui.input_action_button("ok", "OK")))
      ui.modal_show(m)
    
    @reactive.Effect
    @reactive.event(input.ok)
    def removemod():
       ui.modal_remove()

app = App(app_ui, server)
