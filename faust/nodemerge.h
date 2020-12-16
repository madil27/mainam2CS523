#ifndef NODEMERGE_H
#define NODEMERGE_H

#include <bits/stdc++.h>

using namespace std;

class Fap{
private:
  int timestamp;
  unordered_map<string, int> writeTS; // latest time stamp for a file being written
  

public:

  unordered_map<int, unordered_map<string, int>> files;
  Fap();
  /* Getters and Setters */
  void printFap();
  int getTimestamp();
  vector<vector<string>> getSortedFap();
  void setTimestamp(int timestamp);

  /* Functionalities */
  int insert(string log);
  void filter();
};

class FptreeNode{
public:
  string fileId;
  int counter;
  vector<FptreeNode*> children;
  
  FptreeNode(string fileId);
};

class Fptree{
private:
  FptreeNode* root;
  // unordered_map<string, FptreeNode*> siblings;
  int childExist(FptreeNode* node, string& filename);
  void insertRow(vector<string>& row, int idx, FptreeNode* cur);
  void generateCFapHelper(FptreeNode* cur, vector<string>& cfap, vector<vector<string>>& ret);

public:
  Fptree(vector<vector<string>> fap);
  vector<vector<string>> generateCFap();

};

#endif
