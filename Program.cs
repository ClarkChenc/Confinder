using System;
using System.Linq;
using System.Collections.Generic;

using System.Text.RegularExpressions;
using System.Threading;
using System.IO;
using System.Diagnostics;
using System.Security.Permissions;
using System.Text;

namespace SchedulerManager
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                //args = new string[] { @"E:\KLSTND\CC\Research\MonoCeCilTest\TestCase\_BufferWriter\BufferWriter\bin\Debug\BufferWriter.exe" };
            }
            if (args.Length < 1)
            {
                Console.WriteLine("Lack of Tested Program Path");
                Console.WriteLine("Usage:ConFinder.exe <Path>");
                Console.WriteLine("Exit.");
                return;
            }
            string filepath = args[0];

            FileInfo file = new FileInfo(filepath);
            string dir = file.Directory.ToString();
            string filename = Path.GetFileNameWithoutExtension(filepath);
            string mergedfile = Path.Combine(dir, filename + "_merger" + file.Extension);
            string viewerfile = Path.Combine(dir, filename + "_viewer" + file.Extension);


            #region merge

            Process merger = new Process();

            merger.StartInfo.FileName = @"./ILRepack.exe";
            merger.StartInfo.Arguments = "/target:exe" + " /out:" + mergedfile + " " + filepath
                + " ./tools/Method.dll";
            merger.StartInfo.UseShellExecute = false;
            merger.StartInfo.CreateNoWindow = true;
            try
            {
                Console.WriteLine("Mergering.....");
                merger.Start();
                merger.WaitForExit();
            }
            catch (Exception e)
            {
                Console.WriteLine();
                Console.WriteLine("Fail to merge the file.");
                Console.WriteLine("Exit.");
                Thread.Sleep(500);
            }
            Console.WriteLine("Done.");
           // Console.ReadLine();
           
            #endregion

            #region viewer instrumentate
            Console.WriteLine("Instrumentating program.....");
            Console.WriteLine("\tInitializing.....");
            Process viewer = new Process();
            viewer.StartInfo.FileName = @"./Instrument/Instrument.exe";
            string _file = Path.GetFullPath(viewer.StartInfo.FileName);
            viewer.StartInfo.Arguments = mergedfile + " " + viewerfile;
            viewer.StartInfo.UseShellExecute = false;
            try
            {
                viewer.Start();
                viewer.WaitForExit();
            }
            catch (Exception e)
            {
                Console.WriteLine();
                Console.WriteLine("\tFail to instrumentate the file.");
                Console.WriteLine("Exit.");
                Thread.Sleep(500);
            }
            Console.WriteLine("Done.");
         //   Console.ReadLine();
            #endregion

            #region analyzing suspicious interleaving
            TestManager tm = new TestManager(viewerfile);
            tm.MakeTestScheme();
           // Console.ReadLine();

            tm.Search();
            #endregion
            if(File.Exists(mergedfile))
            {
                //File.Delete(mergedfile);
            }

            if (File.Exists(viewerfile))
            {
                //File.Delete(viewerfile);
            }
        }
    }
    public class TestManager
    {
        /// <summary>
        /// key:variableID + ins + threadID
        /// 
        /// val: list SuspiciousInterleavings
        /// </summary>
        Dictionary<string, List<SuspiciousInterleaving>> Collection_exp = new Dictionary<string, List<SuspiciousInterleaving>>();
        Dictionary<string, List<SuspiciousInterleaving>> Collection_exp_single = new Dictionary<string, List<SuspiciousInterleaving>>();

        Dictionary<string, List<SuspiciousInterleaving>> LeftGroup = new Dictionary<string, List<SuspiciousInterleaving>>();

        Dictionary<string, HashSet<string>> WrongTest = new Dictionary<string, HashSet<string>>();

        public string _experimentfile;

        public Dictionary<string, Dictionary<string, SuspiciousInterleaving>> FaultInterleavings = new Dictionary<string, Dictionary<string, SuspiciousInterleaving>>();

        public Dictionary<string, List<SuspiciousInterleaving>> FaultInterleavings2 = new Dictionary<string, List<SuspiciousInterleaving>>();

        public Dictionary<string, HashSet<List<ResultAccess>>> Result = new Dictionary<string, HashSet<List<ResultAccess>>>();

        public TestManager(string experiment_file)
        {
            _experimentfile = experiment_file;
        }

        public void MakeTestScheme()
        {
            Console.WriteLine("Analyzing suspicious interleaving.....");
            List<SuspiciousInterleaving> avoid = new List<SuspiciousInterleaving>();
            TestRunner testrunner = new TestRunner(_experimentfile, null, null);
            testrunner.RunTest();

            if (testrunner.Trace.Accesses.Count > 0)
            {
                PredictFaultAccesses(testrunner.Trace);
                foreach (var patternID in Collection_exp_single.Keys)
                {
                    Collection_exp.Add(patternID, Collection_exp_single[patternID]);
                }
            }
            Console.WriteLine("Done.");
        }
        void PredictFaultAccesses(Trajectory trajectory)
        {
            Collection_exp_single.Clear();
            Dictionary<string, TestGroup> dic_TestGroup = new Dictionary<string, TestGroup>();
            // Dictionary<int, HashSet<string>> dic_thread_variable = new Dictionary<int, HashSet<string>>();
            Dictionary<int, Dictionary<string, Trajectory>> thread_variable_trace = new Dictionary<int, Dictionary<string, Trajectory>>();

            //Dictionary<int, Dictionary<string, Data>> dic_ThreadVariable = new Dictionary<int, Dictionary<string, Data>>();
            List<Hit> susPatterns = new List<Hit>();
            susPatterns.Add(HitRW);
            susPatterns.Add(HitWR);
            susPatterns.Add(HitWW);
            susPatterns.Add(HitRWR);
            susPatterns.Add(HitRWW);
            susPatterns.Add(HitWWR);
            susPatterns.Add(HitWRW);
            susPatterns.Add(HitWWW);

            for (int i = 0; i < trajectory.Accesses.Count; i++)
            {
                //we have to construct dic_thread_variable and thread_varialbe_trace
                //construct thread_variable_trace
                if (!thread_variable_trace.ContainsKey(trajectory.Accesses[i].ThreadID))//if no thread
                {
                    thread_variable_trace[trajectory.Accesses[i].ThreadID] = new Dictionary<string, Trajectory>();
                    //  thread_variable_trace.Add(trajectory.Accesses[i].ThreadID, new Dictionary<string, Trajectory>());
                    thread_variable_trace[trajectory.Accesses[i].ThreadID][trajectory.Accesses[i].VariableID] = new Trajectory();
                    thread_variable_trace[trajectory.Accesses[i].ThreadID][trajectory.Accesses[i].VariableID].Add(trajectory.Accesses[i]);
                }
                else
                {
                    if (!thread_variable_trace[trajectory.Accesses[i].ThreadID].ContainsKey(trajectory.Accesses[i].VariableID))//no variable
                    {
                        thread_variable_trace[trajectory.Accesses[i].ThreadID][trajectory.Accesses[i].VariableID] = new Trajectory();
                        thread_variable_trace[trajectory.Accesses[i].ThreadID][trajectory.Accesses[i].VariableID].Add(trajectory.Accesses[i]);
                    }
                    else
                    {
                        thread_variable_trace[trajectory.Accesses[i].ThreadID][trajectory.Accesses[i].VariableID].Add(trajectory.Accesses[i]);
                    }
                }
            }
            thread_variable_trace = thread_variable_trace.OrderBy(o => o.Key).ToDictionary(o => o.Key, pair => pair.Value);

            #region variable trace test
            //StreamWriter VariableTrace = new StreamWriter(@"C:\Users\Chen\Desktop\Experiment\varialbeTrace.txt", true);
            //foreach (var thrd in thread_variable_trace.Keys)
            //{
            //    foreach (var varb in thread_variable_trace[thrd].Keys)
            //    {
            //        VariableTrace.WriteLine(thrd + " " + varb + ":");
            //        foreach (var ass in thread_variable_trace[thrd][varb].Trace)
            //        {
            //            VariableTrace.WriteLine("\t" + ass.Pattern);
            //        }
            //    }
            //}
            //VariableTrace.Close();
            #endregion

            List<int> threadList = new List<int>();
            foreach (var thread in thread_variable_trace.Keys)
            {
                threadList.Add(thread);
            }

            HashSet<string> sharedVariable = new HashSet<string>();
            for (int i = 0; i < threadList.Count - 1; i++)
            {
                for (int j = i + 1; j < threadList.Count; j++)
                {
                    foreach (var variable in thread_variable_trace[threadList[j]].Keys)
                    {
                        if (thread_variable_trace[threadList[i]].ContainsKey(variable))
                        {
                            sharedVariable.Add(variable);
                            string testGroup_name = threadList[i].ToString() + "_" + threadList[j].ToString() + "_" + variable;
                            TestGroup tg = new TestGroup(testGroup_name);
                            tg.AddListX(thread_variable_trace[threadList[i]][variable].Accesses);
                            tg.AddListY(thread_variable_trace[threadList[j]][variable].Accesses);
                            dic_TestGroup.Add(testGroup_name, tg);
                        }
                    }
                }
            }
            Console.WriteLine(sharedVariable.Count);
            foreach (var tg in dic_TestGroup.Keys)
            {
                for (int i = 0; i < susPatterns.Count; i++)
                {
                    susPatterns[i](dic_TestGroup[tg].Threadx, dic_TestGroup[tg].Thready, trajectory);
                    susPatterns[i](dic_TestGroup[tg].Thready, dic_TestGroup[tg].Threadx, trajectory);
                }
            }
            //Console.WriteLine("Find {0} suspicious interleavings.", SusGroup.Count);
            //StreamWriter Susgroup_record = new StreamWriter(@"C:\Users\Chen\Desktop\Experiment\susgroup.txt", true);
            //foreach(var key in SusGroup.Keys)
            //{
            //    Susgroup_record.WriteLine(key);
            //}
            //Susgroup_record.Close();
        }
        delegate void Hit(List<Access> thread_1, List<Access> thread_2, Trajectory t);

        #region
        void HitRW(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            foreach (var data_1 in thread_1)
            {
                if (data_1.Operation == Operation.Read)
                {
                    foreach (var data_2 in thread_2)
                    {
                        if (data_2.Operation == Operation.Write)
                        {
                            SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { data_1, data_2 });
                            sil.Make();
                            sil.Check(t);
                            if (!sil.IsRight && sil.isFeasible)
                            {
                                if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                {
                                    Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>() { sil });
                                }
                                else
                                {
                                    if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                    {
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitWR(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            foreach (var data_1 in thread_1)
            {
                if (data_1.Operation == Operation.Write)
                {
                    foreach (var data_2 in thread_2)
                    {
                        if (data_2.Operation == Operation.Read)
                        {
                            SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { data_1, data_2 });
                            sil.Make();
                            sil.Check(t);
                            if (!sil.IsRight && sil.isFeasible)
                            {
                                if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                {
                                    Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                    Collection_exp_single[sil.PatternID].Add(sil);
                                }
                                else
                                {
                                    if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                    {
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitWW(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            foreach (var data_1 in thread_1)
            {
                if (data_1.Operation == Operation.Write)
                {
                    foreach (var data_2 in thread_2)
                    {
                        if (data_2.Operation == Operation.Write)
                        {
                            SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { data_1, data_2 });
                            sil.Make();
                            sil.Check(t);
                            if (!sil.IsRight && sil.isFeasible)
                            {
                                if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                {
                                    Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                    Collection_exp_single[sil.PatternID].Add(sil);
                                }
                                else
                                {
                                    if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                    {
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitRWR(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            for (int i = 0; i < thread_1.Count - 1; i++)
            {
                if (thread_1[i].Operation == Operation.Read)
                {
                    for (int j = 0; j < thread_2.Count; j++)
                    {
                        if (thread_2[j].Operation == Operation.Write)
                        {
                            if (thread_1[i + 1].Operation == Operation.Read)
                            {
                                SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { thread_1[i], thread_2[j], thread_1[i + 1] });
                                sil.Make();
                                sil.Check(t);
                                if (!sil.IsRight && sil.isFeasible)
                                {
                                    if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                    {
                                        Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                    else
                                    {
                                        if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                        {
                                            Collection_exp_single[sil.PatternID].Add(sil);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitWWR(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            for (int i = 0; i < thread_1.Count - 1; i++)
            {
                if (thread_1[i].Operation == Operation.Write)
                {
                    for (int j = 0; j < thread_2.Count; j++)
                    {
                        if (thread_2[j].Operation == Operation.Write)
                        {
                            if (thread_1[i + 1].Operation == Operation.Read)
                            {
                                SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { thread_1[i], thread_2[j], thread_1[i + 1] });
                                sil.Make();
                                sil.Check(t);
                                if (!sil.IsRight && sil.isFeasible)
                                {
                                    if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                    {
                                        Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                    else
                                    {
                                        if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                        {
                                            Collection_exp_single[sil.PatternID].Add(sil);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitWRW(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            for (int i = 0; i < thread_1.Count - 1; i++)
            {
                if (thread_1[i].Operation == Operation.Write)
                {
                    for (int j = 0; j < thread_2.Count; j++)
                    {
                        if (thread_2[j].Operation == Operation.Read)
                        {
                            if (thread_1[i + 1].Operation == Operation.Write)
                            {
                                SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { thread_1[i], thread_2[j], thread_1[i + 1] });
                                sil.Make();
                                sil.Check(t);
                                if (!sil.IsRight && sil.isFeasible)
                                {
                                    if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                    {
                                        Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                    else
                                    {
                                        if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                        {
                                            Collection_exp_single[sil.PatternID].Add(sil);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitRWW(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            for (int i = 0; i < thread_1.Count - 1; i++)
            {
                if (thread_1[i].Operation == Operation.Read)
                {
                    for (int j = 0; j < thread_2.Count; j++)
                    {
                        if (thread_2[j].Operation == Operation.Write)
                        {
                            if (thread_1[i + 1].Operation == Operation.Write)
                            {
                                SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { thread_1[i], thread_2[j], thread_1[i + 1] });
                                sil.Make();
                                sil.Check(t);
                                if (!sil.IsRight && sil.isFeasible)
                                {
                                    if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                    {
                                        Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                    else
                                    {
                                        if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                        {
                                            Collection_exp_single[sil.PatternID].Add(sil);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        void HitWWW(List<Access> thread_1, List<Access> thread_2, Trajectory t)
        {
            for (int i = 0; i < thread_1.Count - 1; i++)
            {
                if (thread_1[i].Operation == Operation.Write)
                {
                    for (int j = 0; j < thread_2.Count; j++)
                    {
                        if (thread_2[j].Operation == Operation.Write)
                        {
                            if (thread_1[i + 1].Operation == Operation.Write)
                            {
                                SuspiciousInterleaving sil = new SuspiciousInterleaving(new List<Access> { thread_1[i], thread_2[j], thread_1[i + 1] });
                                sil.Make();
                                sil.Check(t);
                                if (!sil.IsRight && sil.isFeasible)
                                {
                                    if (!Collection_exp_single.ContainsKey(sil.PatternID))
                                    {
                                        Collection_exp_single.Add(sil.PatternID, new List<SuspiciousInterleaving>());
                                        Collection_exp_single[sil.PatternID].Add(sil);
                                    }
                                    else
                                    {
                                        if (!Collection_exp_single[sil.PatternID].Contains(sil))
                                        {
                                            Collection_exp_single[sil.PatternID].Add(sil);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #endregion
        //check all the suspicious interleavings
        //remove the right interleavings from the SusGroup
        //if interleaving is still uncheck when try 5 times, assume the interleaving is unexist
        public void Search()
        {
            Console.WriteLine("Start To Check Suspicious Interleavings.");
            Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            //the dic_group is used to record the suspicious interleavings position in FautInterleavings in order to remove afterwards
            Dictionary<string, List<string>> dic_group = new Dictionary<string, List<string>>();

            Dictionary<string, List<string>> wrong_dic = new Dictionary<string, List<string>>();

            Queue<string> queue_exp = new Queue<string>();
            //List<string> collection_exp_list = new List<string>();

            HashSet<string> correctSet_uniqueID = new HashSet<string>();
            Dictionary<string, SuspiciousInterleaving> dic_cover_uniqueID = new Dictionary<string, SuspiciousInterleaving>();
            int TestIndex = 0;

            for (int r = 1; r <= 1; r++)
            {
                foreach (var patternID in Collection_exp.Keys)
                {
                    queue_exp.Enqueue(patternID);
                }
                correctSet_uniqueID.Clear();
                dic_cover_uniqueID.Clear();
                int failTime = 0;
                int trialTimes = 0;
                //string ExperimentName = Path.Combine(Path.GetDirectoryName(_experimentfile), "ConFinder" + r);
                string ExperimentName = Path.Combine(Path.GetDirectoryName(_experimentfile), "ConFinder_Modify_result");
                

                HashSet<string> set_exp_resultID = new HashSet<string>();
                foreach (var key in Collection_exp.Keys)
                {
                    set_exp_resultID.Add(Collection_exp[key][0].ResultID);
                }

                Dictionary<string, ResultInterleaving> dic_result_resultID = new Dictionary<string, ResultInterleaving>();

                #region runtest

                while (queue_exp.Count != 0)
                {
                    Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
                    HashSet<string> set_result_singleTest = new HashSet<string>();
                    Console.WriteLine(failTime);
                    Console.WriteLine("left :{0}", queue_exp.Count);

                    string testPattern = queue_exp.Dequeue();
                    if (dic_result_resultID.Keys.Contains(Collection_exp[testPattern][0].ResultID))
                    {
                        continue;
                    }
                    trialTimes++;

                    TestRunner t = new TestRunner(_experimentfile, Collection_exp[testPattern], null);
                    t.RunTest();
                    PredictFaultAccesses(t.Trace);

                    foreach (var patternID in Collection_exp_single.Keys)
                    {
                        if (!Collection_exp.Keys.Contains(patternID))
                        {
                            Collection_exp.Add(patternID, Collection_exp_single[patternID]);
                            queue_exp.Enqueue(patternID);
                            set_exp_resultID.Add(Collection_exp[patternID][0].ResultID);
                        }
                    }

                    Console.WriteLine("\tanalyzing...");
                    //get Spectrum
                    foreach (var uniqueID in t.Trace.Interleavings.Keys)
                    {
                        set_result_singleTest.Add(t.Trace.Interleavings[uniqueID].ResultID);
                        if (!dic_result_resultID.Keys.Contains(t.Trace.Interleavings[uniqueID].ResultID))
                        {
                            ResultInterleaving result = new ResultInterleaving(t.Trace.Interleavings[uniqueID]);
                            result.FindSourceCode();
                            dic_result_resultID.Add(t.Trace.Interleavings[uniqueID].ResultID, result);
                        }
                    }
                    //wrong test
                    if (!t.Trace.IsRight)
                    {
                        foreach (var resultID in set_result_singleTest)
                        {
                            dic_result_resultID[resultID].aef++;
                        }
                    }
                    //right test
                    else
                    {
                        foreach (var resultID in set_result_singleTest)
                        {
                            dic_result_resultID[resultID].aep++;
                        }
                    }

                    HashSet<string> wrongSet_uniqueID = new HashSet<string>();
                    //wrong test
                    if (!t.Trace.IsRight)
                    {
                        failTime++;
                        TestIndex++;

                        foreach (var intl_uniqueID in t.Trace.Interleavings.Keys)
                        {
                            //wrong / right classification
                            if (!wrongSet_uniqueID.Contains(intl_uniqueID))
                            {
                                wrongSet_uniqueID.Add(intl_uniqueID);

                                if (!wrong_dic.ContainsKey(intl_uniqueID))
                                {
                                    wrong_dic.Add(intl_uniqueID, new List<string>() { TestIndex.ToString() });
                                }
                                else
                                {
                                    wrong_dic[intl_uniqueID].Add(TestIndex.ToString());
                                }
                            }
                            //spectrum classification
                            if (!dic_cover_uniqueID.ContainsKey(intl_uniqueID))
                            {
                                dic_cover_uniqueID.Add(intl_uniqueID, t.Trace.Interleavings[intl_uniqueID]);
                            }
                            dic_cover_uniqueID[intl_uniqueID].aef++;
                        }
                        WrongTest.Add(TestIndex.ToString(), wrongSet_uniqueID);
                    }
                    else //right test
                    {
                        foreach (var intl_uniqueID in t.Trace.Interleavings.Keys)
                        {
                            //wrong / right classification
                            if (!correctSet_uniqueID.Contains(intl_uniqueID))
                            {
                                correctSet_uniqueID.Add(intl_uniqueID);
                            }
                            //spectrum classification
                            if (!dic_cover_uniqueID.ContainsKey(intl_uniqueID))
                            {
                                dic_cover_uniqueID.Add(intl_uniqueID, t.Trace.Interleavings[intl_uniqueID]);
                            }
                            dic_cover_uniqueID[intl_uniqueID].aep++;
                        }
                    }
                    //Console.WriteLine("{0}/{1}", hitcoount, totalcount);
                    Console.WriteLine("\tFinish analyzing...");
                    Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++");

                }
                #endregion
                StreamWriter sw = new StreamWriter(Path.Combine(Path.GetDirectoryName(_experimentfile), "TrialTime_modify.txt"), true);
                sw.WriteLine(trialTimes + "\t" + failTime + "\t" + set_exp_resultID.Count + "\t" + dic_result_resultID.Count);
                sw.Close();
                Console.WriteLine(failTime);
                #region wrong / right classification
                //    DisplayInterleavings(WrongTest, Interleavings, Path.Combine(Path.GetDirectoryName(_experimentfile), "interleavings_result1.txt"));
                foreach (var key in correctSet_uniqueID)
                {
                    if (wrong_dic.ContainsKey(key))
                    {
                        foreach (var wrongtest_key in wrong_dic[key])
                        {
                            WrongTest[wrongtest_key].Remove(key);
                        }
                    }
                }
                //  DisplayInterleavings(WrongTest, Interleavings, Path.Combine(Path.GetDirectoryName(_experimentfile), "interleavings_result2.txt"));
                // DisplayPattern(WrongTest, dic_cover_uniqueID, Path.Combine(ExperimentName, "wrong_pattern.txt"));
                //  MergeAndDisplayPattern(WrongTest, Interleavings, Path.Combine(Path.GetDirectoryName(_experimentfile), "Pattern.txt"));
                //DisplayCorrect(Collection_exp, correctSet_uniqueID, Path.Combine(ExperimentName, "Correct.txt"));
                //spectrum classification
                #endregion

                #region just calculate wrongset score
                //Dictionary<string, SuspiciousInterleaving> dic_wrongintel_uniqueID = new Dictionary<string, SuspiciousInterleaving>();
                //foreach (var item in dic_cover_uniqueID.Keys)
                //{
                //    if (!correctSet_uniqueID.Contains(item))
                //    {
                //        dic_wrongintel_uniqueID.Add(item, dic_cover_uniqueID[item]);
                //    }
                //}
                //     Spectrum(WrongCol, susinterleavings.Count);
                #endregion

                //DeleteBenignInterleavings(Interl_result);

                //if (Directory.Exists(ExperimentName))
                //{
                //    Directory.Delete(ExperimentName, true);
                //}
                Directory.CreateDirectory(ExperimentName);
                ShowSpectrumIns(dic_result_resultID, trialTimes, failTime, ExperimentName);

                Console.WriteLine("Done.");
            //    Console.ReadLine();
                //}
            }
        }
        public void DeleteBenignInterleavings(Dictionary<string, ResultInterleaving> Interleavings)
        {
        }
        //    List<string> interleavingList = new List<string>();
        //    HashSet<string> deleteList = new HashSet<string>();
        //    foreach (var key in Interleavings.Keys)
        //    {
        //        interleavingList.Add(key);
        //    }
        //    for (int i = 0; i < interleavingList.Count; i++)
        //    {
        //        if (Interleavings[interleavingList[i]].Accesses.Count == 2)
        //        {
        //            string currentName = Interleavings[interleavingList[i]].Accesses[0] + Interleavings[interleavingList[i]].Instructions[1];
        //            if (Interleavings.ContainsKey(currentName))
        //            {

        //            }
        //            string reverseName = Interleavings[interleavingList[i]].Instructions[1] + Interleavings[interleavingList[i]].Instructions[0];
        //            if (Interleavings.ContainsKey(reverseName) && Interleavings[currentName].aef != 0 && Interleavings[reverseName].aef != 0)
        //            {
        //                if (!deleteList.Contains(reverseName))
        //                {
        //                    deleteList.Add(currentName);
        //                    deleteList.Add(reverseName);
        //                }
        //            }
        //        }
        //    }
        //    foreach (var key in deleteList)
        //    {
        //        Interleavings[key].aef = 0;
        //    }
        //}

        public void ShowSpectrumIntl(Dictionary<string, SuspiciousInterleaving> Interleavings, int trialCount)
        {
            List<string> interleavings = new List<string>();
            foreach (var intl in Interleavings.Keys)
            {
                interleavings.Add(intl);
            }
            for (int i = 0; i < interleavings.Count; i++)
            {
                Interleavings[interleavings[i]].CalculateSus(trialCount);
            }

            //sort
            for (int i = 0; i < interleavings.Count - 1; i++)
            {
                for (int j = i; j < interleavings.Count; j++)
                {
                    if (Interleavings[interleavings[i]].score < Interleavings[interleavings[j]].score)
                    {
                        string temp = interleavings[i];
                        interleavings[i] = interleavings[j];
                        interleavings[j] = temp;
                    }
                }
            }
            StreamWriter sw = new StreamWriter(Path.Combine(Path.GetDirectoryName(_experimentfile), "Spectrum.txt"), true);
            for (int i = 0; i < interleavings.Count; i++)
            {
                sw.WriteLine("Interleaving " + i + ":" + Interleavings[interleavings[i]].score);
                for (int j = 0; j < Interleavings[interleavings[i]].Interleaving.Count; j++)
                {
                    sw.WriteLine("\t" + Interleavings[interleavings[i]].Interleaving[j]);
                }
            }
            sw.Close();
        }
        public void ShowSpectrumIns(Dictionary<string, ResultInterleaving> Interl_result, int trialCount, int failCount, string filepath)
        {
            List<string> interleavings = new List<string>();
            foreach (var key in Interl_result.Keys)
            {
                interleavings.Add(key);
            }

            for (int i = 0; i < interleavings.Count; i++)
            {
                Interl_result[interleavings[i]].Calculate(trialCount, failCount);
            }
            //sort
            for (int i = 0; i < interleavings.Count - 1; i++)
            {
                for (int j = i; j < interleavings.Count; j++)
                {
                    if (Interl_result[interleavings[i]].Score < Interl_result[interleavings[j]].Score)
                    {
                        string temp = interleavings[i];
                        interleavings[i] = interleavings[j];
                        interleavings[j] = temp;
                    }
                }
            }
            List<ResultInterleaving> resultList = new List<ResultInterleaving>();
            for(int i = 0; i < interleavings.Count; i ++)
            {
                //if(Interl_result[interleavings[i]].Score == 0)break;
                resultList.Add(Interl_result[interleavings[i]]);
            }

            string frameworkPath = "./reportformat.html";
            string desPath = Path.Combine(filepath, "BugReport.html");
            GenerateReport gr = new GenerateReport(frameworkPath, desPath, resultList);
            gr.Make();

            /*
            StreamWriter sw;
            sw = new StreamWriter(Path.Combine(filepath, "SpectrumIntl.txt"), false);
            if (Interl_result[interleavings[0]].Score == 0)
            {
                sw.WriteLine("No fault.");
            }
            else
            {
                for (int i = 0; i < interleavings.Count; i++)
                {
                    sw.WriteLine("Interleaving " + i + " ----\tScore: " + Interl_result[interleavings[i]].Score);
                    sw.WriteLine("\t" + Interl_result[interleavings[i]].Accesses[0].VariableName);
                    for (int j = 0; j < Interl_result[interleavings[i]].Accesses.Count; j++)
                    {
                        sw.WriteLine("\t" + Interl_result[interleavings[i]].Accesses[j].Operation + "\t" + Interl_result[interleavings[i]].Accesses[j].MethodName + "\t"
                            + Interl_result[interleavings[i]].Accesses[j].startline + "\t\t" + Interl_result[interleavings[i]].Accesses[j].SourceCode);
                    }
                }
            }
            sw.Close();*/
        }
        public void DisplayCorrect(Dictionary<string, List<SuspiciousInterleaving>> Sus, HashSet<string> Correct, string filepath)
        {
            StreamWriter sw = new StreamWriter(filepath, true);

            int interleavingCount = 0;
            foreach (var key in Sus.Keys)
            {
                for (int i = 0; i < Sus[key].Count; i++)
                {
                    if (Correct.Contains(Sus[key][i].UniqueID))
                    {
                        interleavingCount++;
                        sw.WriteLine("Intereaving {0}", interleavingCount);
                        foreach (var sus in Sus[key][i].Interleaving)
                        {
                            sw.WriteLine("\t" + sus);
                        }
                    }
                }
            }

            sw.Close();
        }
        void DisplayInterleavings(Dictionary<string, HashSet<string>> wrong, Dictionary<string, SuspiciousInterleaving> interleavings, string filepath)
        {
            StreamWriter sw = new StreamWriter(filepath, true);
            int GroupCount = 0;
            foreach (var group in wrong.Keys)
            {
                GroupCount++;
                sw.WriteLine("Group {0}", GroupCount);

                int InterLeavingsCount = 0;
                foreach (var interleaving in wrong[group])
                {
                    InterLeavingsCount++;
                    sw.WriteLine("\tInterleavings {0}", InterLeavingsCount);
                    foreach (var sus in interleavings[interleaving].Interleaving)
                    {
                        sw.WriteLine("\t\t" + sus);
                    }
                }
            }
            sw.Close();
        }
        void DisplayPattern(Dictionary<string, HashSet<string>> wrong, Dictionary<string, SuspiciousInterleaving> Interleavings, string filepath)
        {
            StreamWriter sw = new StreamWriter(filepath, true);

            int GroupNum = 0;
            foreach (var group in wrong.Keys)
            {
                GroupNum++;
                sw.WriteLine("Group {0}:", GroupNum);
                HashSet<string> Pattern = new HashSet<string>();

                int PatternNum = 0;
                foreach (var interleaving in wrong[group])
                {
                    if (!Pattern.Contains(Interleavings[interleaving].PatternID))
                    {
                        PatternNum++;
                        sw.WriteLine("\tPattern {0}", PatternNum);
                        Pattern.Add(Interleavings[interleaving].PatternID);
                        foreach (var acc in Interleavings[interleaving].Result)
                        {
                            sw.WriteLine("\t" + acc.Instruction);
                        }
                    }
                }
            }
            sw.Close();
        }
        void MergeAndDisplayPattern(Dictionary<string, HashSet<string>> wrong, Dictionary<string, SuspiciousInterleaving> Interleavings, string filepath)
        {
            Dictionary<string, Dictionary<string, List<ResultAccess>>> Groups = new Dictionary<string, Dictionary<string, List<ResultAccess>>>();

            HashSet<string> MinimumFactor = new HashSet<string>();
            HashSet<string> MultiGroup = new HashSet<string>();

            foreach (var group in wrong.Keys)
            {
                Dictionary<string, List<ResultAccess>> Group = new Dictionary<string, List<ResultAccess>>();
                foreach (var interleaving in wrong[group])
                {
                    if (!Group.ContainsKey(Interleavings[interleaving].ResultID))
                    {
                        Group.Add(Interleavings[interleaving].ResultID, Interleavings[interleaving].Result);
                    }
                }
                if (Group.Count == 0)
                    continue;

                Group = Group.OrderBy(p => p.Key).ToDictionary(p => p.Key, pair => pair.Value);
                string name = "";
                foreach (var key in Group.Keys)
                {
                    name += key;
                }
                if (!Groups.ContainsKey(name))
                {
                    Groups.Add(name, Group);
                }

                if (Group.Count == 1)
                {
                    if (!MinimumFactor.Contains(name))
                    {
                        MinimumFactor.Add(name);
                    }
                }
                else
                {
                    if (!MultiGroup.Contains(name))
                    {
                        MultiGroup.Add(name);
                    }
                }
            }
            Groups = Groups.OrderBy(p => p.Key).ToDictionary(p => p.Key, pair => pair.Value);

            UpdateGroups(Groups, MinimumFactor, MultiGroup);

            StreamWriter sw = new StreamWriter(filepath, true);
            int GroupNum = 0;
            foreach (var group in Groups.Keys)
            {
                GroupNum++;
                sw.WriteLine("Group {0}", GroupNum);
                int PatternNum = 0;
                foreach (var pattern in Groups[group].Keys)
                {
                    PatternNum++;
                    sw.WriteLine("\tPattern {0}", PatternNum);
                    foreach (var acc in Groups[group][pattern])
                    {
                        sw.WriteLine("\t\t" + acc.Instruction);
                    }
                }
            }
            sw.Close();
        }
        void UpdateGroups(Dictionary<string, Dictionary<string, List<ResultAccess>>> Groups, HashSet<string> Single, HashSet<string> Multi)
        {
            if (Multi.Count == 0)
                return;
            bool isDone = true;
            do
            {
                isDone = true;
                List<string> multiList = new List<string>();
                foreach (var key in Multi)
                {
                    multiList.Add(key);
                }

                //handle with ith multiList
                for (int i = 0; i < multiList.Count; i++)
                {
                    //decompose targetGroup
                    List<string> InterleavingsInMulti = new List<string>();
                    foreach (var interleaving in Groups[multiList[i]].Keys)
                    {
                        InterleavingsInMulti.Add(interleaving);
                    }
                    //Interleavings indicate the target group's interleavings
                    for (int j = 0; j < InterleavingsInMulti.Count; j++)
                    {
                        if (Single.Contains(InterleavingsInMulti[j]))
                        {
                            isDone = false;
                            Dictionary<string, List<ResultAccess>> targetGroup = Groups[multiList[i]];
                            //remove the orginal
                            Multi.Remove(multiList[i]);
                            Groups.Remove(multiList[i]);
                            targetGroup.Remove(InterleavingsInMulti[j]);
                            //generate new name
                            string newname = "";
                            foreach (var key in targetGroup.Keys)
                            {
                                newname += key;
                            }
                            //update Single
                            if (targetGroup.Count == 1)
                            {
                                if (!Single.Contains(newname))
                                {
                                    Single.Add(newname);
                                }
                            }
                            //update Multi
                            else
                            {
                                if (!Multi.Contains(newname))
                                {
                                    Multi.Add(newname);
                                }
                            }
                            //update Groups
                            multiList[i] = newname;
                            if (!Groups.ContainsKey(newname))
                            {
                                Groups.Add(newname, targetGroup);
                            }


                        }
                    }
                }
            } while (!isDone);
        }
        void DisplayInterleavg(Dictionary<string, List<SuspiciousInterleaving>> Interleavings, string filepath)
        {
            StreamWriter sw = new StreamWriter(filepath, true);

            int interleavings_count = 0;
            foreach (var key in Interleavings.Keys)
            {
                sw.WriteLine("Interleaving {0}:", interleavings_count);
                sw.WriteLine("there are {0}", Interleavings[key].Count);
                for (int i = 0; i < Interleavings[key].Count; i++)
                {
                    sw.WriteLine(i);
                    for (int j = 0; j < Interleavings[key][i].Interleaving.Count; j++)
                    {
                        sw.Write("\t" + Interleavings[key][i].Result[j].ThreadID + "~" + Interleavings[key][i].Result[j].Instruction + "\t" + Interleavings[key][i].Result[j].Index + "\n");
                    }
                }
                interleavings_count++;
            }
            sw.Close();
        }
        #region
        //Dictionary<string, Dictionary<string, SuspiciousInterleaving>> DecomposeNet(Dictionary<string, SuspiciousInterleaving> father, Dictionary<string, SuspiciousInterleaving> RightGroup, List<string> MinGroup)
        //{
        //    Dictionary<string, Dictionary<string, SuspiciousInterleaving>> ChildNet = new Dictionary<string, Dictionary<string, SuspiciousInterleaving>>();
        //    List<SuspiciousInterleaving> _fatherList = new List<SuspiciousInterleaving>();
        //    string name = null;
        //    foreach (var key in father)
        //    {
        //        name += key;
        //    }
        //    foreach (var sus in father.Values)
        //    {
        //        _fatherList.Add(sus);
        //    }
        //    for (int i = 0; i < _fatherList.Count; i++)
        //    {
        //        if (RightGroup.ContainsKey(_fatherList[i].PatternID))
        //            continue;
        //        Console.WriteLine("{0}/{1}", i, _fatherList.Count);
        //        List<SuspiciousInterleaving> avoid = new List<SuspiciousInterleaving>();
        //        for (int j = 0; j < _fatherList.Count; j++)
        //        {
        //            if (!RightGroup.ContainsKey(_fatherList[j].PatternID))
        //            {
        //                if (j != i)
        //                {
        //                    avoid.Add(_fatherList[j]);
        //                }
        //            }
        //        }
        //        TestRunner t = new TestRunner(_experimentfile, _fatherList[i], avoid);
        //        t.RunTest();

        //        Dictionary<string, SuspiciousInterleaving> childdic = new Dictionary<string, SuspiciousInterleaving>();
        //        for (int j = 0; j < _fatherList.Count; j++)
        //        {
        //            if (RightGroup.ContainsKey(_fatherList[j].PatternID))
        //                continue;
        //            _fatherList[j].Check(t.Trace);
        //            if (_fatherList[j].IsChecked)
        //            {
        //                if (!_fatherList[j].IsRight && !childdic.ContainsKey(_fatherList[j].PatternID))
        //                {
        //                    childdic.Add(_fatherList[j].PatternID, _fatherList[j]);
        //                }
        //                else
        //                {
        //                    RightGroup.Add(_fatherList[j].PatternID, _fatherList[j]);
        //                }
        //            }
        //        }
        //        //add to ChildNet
        //        childdic = childdic.OrderBy(o => o.Key).ToDictionary(o => o.Key, pair => pair.Value);

        //        string _id = null;
        //        foreach (var key in childdic.Keys)
        //        {
        //            _id += key;
        //        }
        //        if (_id != null)
        //        {
        //            if (!ChildNet.ContainsKey(_id))
        //            {
        //                ChildNet.Add(_id, childdic);
        //            }
        //        }
        //    }
        //    List<Tuple<string, string>> Name = new List<Tuple<string, string>>();
        //    //Remove the right interleavings
        //    if (RightGroup.Count != 0)
        //    {
        //        UpdateFaultInterleavings(RightGroup, ChildNet, Name);
        //    }

        //    foreach (var key in ChildNet.Keys)
        //    {
        //        if (ChildNet[key].Count == 1)
        //        {
        //            MinGroup.Add(key);
        //        }
        //    }
        //    if (ChildNet.Count == 0)
        //    {
        //        ChildNet = DecomposeNet(father, RightGroup, MinGroup);
        //    }

        //    if (ChildNet.Count == 1)
        //    {
        //        string key = ChildNet.Keys.First(k => k != null);
        //        if (ChildNet[key].Count == father.Count)
        //        {
        //            bool isSame = true;

        //            foreach (var sus in ChildNet[key].Keys)
        //            {
        //                if (!father.ContainsKey(sus))
        //                {
        //                    isSame = false;
        //                    break;
        //                }
        //            }
        //            if (isSame)
        //            {
        //                MinGroup.Add(key);
        //            }
        //        }
        //    }
        //    else
        //    {
        //        string _name = null;
        //        foreach (var key in ChildNet.Keys)
        //        {
        //            if (key == name)
        //            {
        //                _name = name;
        //                MinGroup.Add(key);
        //                break;
        //            }
        //        }
        //    }
        //    return ChildNet;
        //}
        #endregion
        public void ShowResult(string fileapth)
        {
            //StreamWriter sw = new StreamWriter(Path.Combine(Path.GetDirectoryName(_experimentfile), Path.GetFileNameWithoutExtension(_experimentfile) + "_result.txt"), true);
            StreamWriter sw = new StreamWriter(fileapth, true);
            sw.WriteLine("Fault interleaving is:");
            int group_count = 0;
            foreach (var key in Result.Keys)
            {
                sw.WriteLine("Group" + group_count + ":");
                int interleaving_count = 0;
                foreach (var interleaving in Result[key])
                {
                    sw.WriteLine("Interleaving {0}:", interleaving_count);
                    foreach (var sus in interleaving)
                    {
                        sw.Write(sus.Instruction + "\t");
                    }
                    sw.WriteLine();
                    interleaving_count++;
                }
                sw.WriteLine();
                Console.WriteLine();
                group_count++;
            }
            if (group_count == 0)
            {
                sw.WriteLine("None:");
            }
            sw.Close();
        }
    }
    public class TestRunner
    {
        public Trajectory Trace
        {
            get { return _trace; }
        }

        Trajectory _trace;
        AppDomain _app;
        bool _isRight = true;

        public bool IsSuccess = true;

        List<SuspiciousInterleaving> _expect;
        List<SuspiciousInterleaving> _avoid; // this maybe have a chance to optimize
        string _filename;
        Thread test_thrd;
        Thread communication_thrd;
        string message = null;
        IPCStringStream _server_stream;
        public TestRunner(string filename, List<SuspiciousInterleaving> expect, List<SuspiciousInterleaving> avoid)
        {
            _filename = filename;
            _expect = expect;
            _avoid = avoid;
            _app = AppDomain.CreateDomain("Test");
            _app.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs args)
            {
                Console.WriteLine("unHandled exception");
                // RunTest();
            };
            // _server_stream = new IPCStringStream(_app.Id.ToString(), 2048, true);
            _server_stream = new IPCStringStream("Test", 1024 * 1024, true);

            _trace = new Trajectory();

            //if(File.Exists(@"C:\Users\Chen\Desktop\Experiment\deadlock.txt"))
            //{
            //    File.Delete(@"C:\Users\Chen\Desktop\Experiment\deadlock.txt");
            //}

            //if (File.Exists(@"E:\KLSTND\CC\Research\MonoCeCilTest\account\bin\Debug\trace.txt"))
            //{
            //    File.Delete(@"E:\KLSTND\CC\Research\MonoCeCilTest\account\bin\Debug\trace.txt");
            //}
        }
        public void RunTest()
        {
            //StreamWriter runner = new StreamWriter(@"C:\Users\Chen\Desktop\Experiment\runner.txt", true);
            //runner.WriteLine("before run");
            //runner.Flush();
            test_thrd = new Thread(runtest);
            communication_thrd = new Thread(communicate);
            //Console.WriteLine("before run");
            //Console.ReadLine();
            Console.WriteLine("\tRun test.....");
            test_thrd.Start();
            communication_thrd.Start();

            communication_thrd.Join();
            //Console.WriteLine("finish run");
            //string s;
            //do
            //{
            //    s = Console.ReadLine();
            //} while (s != "e");
            //runner.WriteLine("finish run");
            //runner.Flush();
            //runner.Close();
            try
            {
                AppDomain.Unload(_app);
                _server_stream.Dispose();
            }
            catch (Exception e)
            {
                Console.WriteLine("Can't run.");
                // Console.Read();
            }

            if (message == null)
                return;
            string[] strlens = message.Split('$');

            Regex rg = new Regex(@"^(.*?)\t(\w*)\t(\d*)\tThread(.*?)\tLock(.*?)\t(.*?)\tURL(.*?)\tsL(\d+)\teL(\d+)\tsC(\d+)\teC(\d+)~(\d+)");
            // Regex rg = new Regex(@"^(.*?)\t(\w*)\t(\d*)\tThread(.*?)\tLock(.*?)\t(.*?)~(\d+)");
            Regex rg_thread = new Regex(@"-(\d+)");
            Regex rg_lock = new Regex(@"-(\d+)\((\d+)\)");
            Regex rg_variable_function = new Regex(@"^.*?\s.*?\s(.*?)@@(.*?)$");
            MatchCollection mc_collection;

            List<Access> trace = new List<Access>();
            foreach (var line in strlens)
            {
                if (line != "")
                {
                    string operation;
                    Match match = rg.Match(line);
                    if (match != null)
                    {
                        operation = operation = (match.Groups[2].Value);
                        if (operation == "stfld" || operation == "ldfld" || operation == "stsfld" || operation == "ldsfld")
                        {
                            string variableID = match.Groups[1].Value;
                            int threadID = Convert.ToInt32(match.Groups[3].Value);
                            string ins = match.Groups[6].Value;
                            //int index = Convert.ToInt32(match.Groups[7].Value);
                            Match match_variable_function = rg_variable_function.Match(ins);
                            string variableName = match_variable_function.Groups[1].Value;
                            string methodName = match_variable_function.Groups[2].Value;
                            

                            int index = Convert.ToInt32(match.Groups[12].Value);

                            string URL = match.Groups[7].Value;
                            int startLine = Convert.ToInt32(match.Groups[8].Value);
                            int endLine = Convert.ToInt32(match.Groups[9].Value);
                            int startCol = Convert.ToInt32(match.Groups[10].Value);
                            int endCol = Convert.ToInt32(match.Groups[11].Value);

                            Restrain res = new Restrain();
                            string thrdstate = match.Groups[4].Value;
                            mc_collection = rg_thread.Matches(thrdstate);
                            foreach (Match _thrd in mc_collection)
                            {
                                res.ThreadState.Add(Convert.ToInt32(_thrd.Groups[1].Value));
                            }
                            string lockstate = match.Groups[5].Value;
                            mc_collection = rg_lock.Matches(lockstate);
                            foreach (Match _loc in mc_collection)
                            {
                                Lock _lock = new Lock(_loc.Groups[1].Value, _loc.Groups[2].Value);
                                res.LockState.Add(_lock);
                            }
                            Access data = new Access(variableID, operation, threadID, res,variableName, methodName,
                                ins, index, URL, startLine, endLine, startCol, endCol);
                            // Data data = new Data(variableID, operation, threadID, res, ins, index);
                            trace.Add(data);
                        }
                    }
                }
            }
            _trace = new Trajectory(trace, _isRight);

            Console.WriteLine("\tFinish test...");
            // Console.ReadLine();
        }
        void runtest()
        {
            int startTime = DateTime.Now.Minute * 60 * 1000 + DateTime.Now.Second * 1000 + DateTime.Now.Millisecond;
            // _app.UnhandledException += _app_UnhandledException;
            _isRight = true;
            try
            {
                _app.ExecuteAssembly(_filename);
            }
            catch (Exception e)
            {
                Console.WriteLine("bug");
                if (!e.ToString().Contains("bug"))
                {
                    Console.WriteLine("error.");
                }
                Console.WriteLine("\tfind bug!");
                _isRight = false;
            }
            int endTime = DateTime.Now.Minute * 60 * 1000 + DateTime.Now.Second * 1000 + DateTime.Now.Millisecond;
            string record = Path.GetFileNameWithoutExtension(_filename);
            //StreamWriter sw = new StreamWriter(@"C:\Users\Chen\Desktop\Experiment\span_" + record + ".txt", true);
            //sw.WriteLine(endTime - startTime);
            //sw.Close();
            _server_stream.StopWaitingIncoming();
            //test is done.
        }

        void communicate()
        {
            StringBuilder scheduleBuilder = new StringBuilder(1024);
            string schedule = "";
            //get schedule
            if (_expect != null)
            {
                for (int i = 0; i < _expect.Count; i++)
                {
                    scheduleBuilder.Append("expect:");
                    //schedule += "expect:";
                    // StreamWriter test = new StreamWriter(@"C:\Users\Chen\Desktop\Experiment\send_schedule.txt", true);
                    // test.WriteLine("send_expect:\t");
                    for (int j = 0; j < _expect[i].Interleaving.Count; j++)
                    {
                        //test.WriteLine(_expect._sus[i]._variableID + "\t" + _expect._sus[i]._ins + "\t" + _expect._sus[i]._threadID + "\t");
                        scheduleBuilder.Append(_expect[i].Interleaving[j] + "##");
                        //schedule += _expect[i].Interleaving[j] + "##"; //each access is seperated by ##
                        //test.WriteLine(_expect.Interleaving[i]);
                    }
                    // test.Close();
                    scheduleBuilder.Append("\n");
                    //schedule += "\n";
                    // test.Flush();
                    // test.Close();
                    schedule = scheduleBuilder.ToString();
                    scheduleBuilder.Clear();
                    _server_stream.WriteLine(schedule);
                    _server_stream.Flush();
                    schedule = null;
                }
            }
            if (_avoid != null)
            {
                for (int i = 0; i < _avoid.Count; i++)
                {
                    scheduleBuilder.Append("avoid:");
                    //schedule += "avoid:";
                    for (int j = 0; j < _avoid[i].Interleaving.Count; j++)
                    {
                        scheduleBuilder.Append(_avoid[i].Interleaving[j] + "##");
                        //schedule += _avoid[i].Interleaving[j] + "##";  // each access
                    }
                    scheduleBuilder.Append("\n");
                    //schedule += "\n";
                    schedule = scheduleBuilder.ToString();
                    scheduleBuilder.Clear();
                    _server_stream.WriteLine(schedule);
                    _server_stream.Flush();
                    schedule = null;
                }
            }
            schedule = "stop";
            _server_stream.WriteLine(schedule);
            _server_stream.Flush();

            StringBuilder receiveMessage = new StringBuilder();
            #region receive data
            try
            {
                while (true)
                {
                    string data = null;
                    data = _server_stream.ReadLine();
                    if (data != null)
                    {
                        receiveMessage.Append(data);
                    }
                    else
                    {
                        break;
                    }
                }
                message = receiveMessage.ToString();
            }
            catch
            {
            }
            #endregion
        }
    }
    public class GenerateReport
    {
        string _report;
        string _desPath;
        List<ResultInterleaving> _resultList = new List<ResultInterleaving>();
        public GenerateReport(string framework_path, string desPath,  List<ResultInterleaving> resultInterleavings)
        {
            StringBuilder report = new StringBuilder();
            string framework = File.ReadAllText(framework_path);
            report.Append(framework);
            _report = report.ToString();
            _desPath = desPath;
            for(int i = 0; i < resultInterleavings.Count; i++)
            {
                if (resultInterleavings[i].Score == 0) break;
                _resultList.Add(resultInterleavings[i]);
            }
        }
        public void Make()
        {
            StringBuilder content = new StringBuilder();
            if(_resultList.Count == 0)
            {
                NoFault nf = new NoFault();
                content.Append(nf.Content);
            }
            else
            {
                for(int i = 0; i < _resultList.Count; i++)
                {
                    if(_resultList[i].Accesses.Count ==2)
                    {
                        TwoAccess item = new TwoAccess(_resultList[i].Score.ToString(), _resultList[i].Accesses[0].VariableName,
                            new string[2] { _resultList[i].Accesses[0].Operation, _resultList[i].Accesses[1].Operation },
                            new string[2] { _resultList[i].Accesses[0].MethodName, _resultList[i].Accesses[1].MethodName },
                            new string[2] { _resultList[i].Accesses[0].startline.ToString(), _resultList[i].Accesses[1].startline.ToString() },
                            new string[2] { _resultList[i].Accesses[0].SourceCode, _resultList[i].Accesses[1].SourceCode });
                        content.Append(item.Content);
                    }
                    else
                    {
                        ThreeAccess item = new ThreeAccess(_resultList[i].Score.ToString(), _resultList[i].Accesses[0].VariableName,
                            new string[3] { _resultList[i].Accesses[0].Operation, _resultList[i].Accesses[1].Operation, _resultList[i].Accesses[2].Operation },
                            new string[3] { _resultList[i].Accesses[0].MethodName, _resultList[i].Accesses[1].MethodName, _resultList[i].Accesses[2].MethodName },
                            new string[3] { _resultList[i].Accesses[0].startline.ToString(), _resultList[i].Accesses[1].startline.ToString(), _resultList[i].Accesses[2].startline.ToString() },
                        new string[3] { _resultList[i].Accesses[0].SourceCode, _resultList[i].Accesses[1].SourceCode, _resultList[i].Accesses[2].SourceCode });
                        content.Append(item.Content);
                    }
                }
            }
            _report = _report.Replace("MyContent", content.ToString());
            StreamWriter sw = new StreamWriter(_desPath, false);
            sw.WriteLine(_report.ToString());
            sw.Close();
        }
        class TwoAccess
        {
            string _rank;
            string _variable = null;
            string[] _accessType = new string[2];
            string[] _method = new string[2];
            string[] _lineNum = new string[2];
            string[] _statement = new string[2];
            StringBuilder content = new StringBuilder();
            public TwoAccess(string rank, string variable, string[] accessType, string[] method, string[] lineNum, string[] statement)
            {
                _rank = rank.ToString();
                _variable = variable;
                _accessType = accessType;
                _method = method;
                _lineNum = lineNum;
                _statement = statement;
                Make();
            }
            void Make()
            {
                content.Append("<tr>");
                content.Append("<th scope=\"row\" abbr=\"Model\" class=\"spec\" rowspan=\"2\">" + _rank + "</th>");
                content.Append("<td rowspan=\"2\">" + _variable + "</td>");
                content.Append("<td>" + _accessType[0] + "</td>");
                content.Append("<td>" + _method[0] + "</td>");
                content.Append("<td>" + _lineNum[0] + "</td>");
                content.Append("<td>" + _statement[0] + "</td>");
                content.Append("</tr>");
                content.Append("<tr>");
                content.Append("<td>" + _accessType[1] + "</td>");
                content.Append("<td>" + _method[1] + "</td>");
                content.Append("<td>" + _lineNum[1] + "</td>");
                content.Append("<td>" + _statement[1] + "</td>");
                content.Append("</tr>");
                content.ToString();
            }
            public string Content
            {
                get { return content.ToString(); }
            }
        }
        class ThreeAccess
        {
            string _rank;
            string _variable = null;
            string[] _accessType = new string[3];
            string[] _method = new string[3];
            string[] _lineNum = new string[3];
            string[] _statement = new string[3];
            StringBuilder content = new StringBuilder();
            public ThreeAccess(string rank, string variable, string[] accessType, string[] method, string[] lineNum, string[] statement)
            {
                _rank = rank.ToString();
                _variable = variable;
                _accessType = accessType;
                _method = method;
                _lineNum = lineNum;
                _statement = statement;
                Make();
            }
            void Make()
            {
                content.Append("<tr>");
                content.Append("<th scope=\"row\" abbr=\"Model\" class=\"spec\" rowspan=\"3\">" + _rank + "</th>");
                content.Append("<td rowspan=\"3\">" + _variable + "</td>");
                content.Append("<td>" + _accessType[0] + "</td>");
                content.Append("<td>" + _method[0] + "</td>");
                content.Append("<td>" + _lineNum[0] + "</td>");
                content.Append("<td>" + _statement[0] + "</td>");
                content.Append("</tr>");
                content.Append("<tr>");
                content.Append("<td>" + _accessType[1] + "</td>");
                content.Append("<td>" + _method[1] + "</td>");
                content.Append("<td>" + _lineNum[1] + "</td>");
                content.Append("<td>" + _statement[1] + "</td>");
                content.Append("</tr>");
                content.Append("<tr>");
                content.Append("<td>" + _accessType[2] + "</td>");
                content.Append("<td>" + _method[2] + "</td>");
                content.Append("<td>" + _lineNum[2] + "</td>");
                content.Append("<td>" + _statement[2] + "</td>");
                content.Append("</tr>");
                content.ToString();
            }
            public string Content
            {
                get { return content.ToString(); }
            }
        }
        class NoFault
        {
            StringBuilder content = new StringBuilder();
            public NoFault()
            {
                content.Append("<tr>");
                content.Append("<center>");
                content.Append("<th scope=\"row\" abbr=\"Model\" class=\"spec\" rowspan=\"2\" colspan=\"6\" align=\"center\">" + "No Fault Detected" + "</th>");
                content.Append("</center>");
                content.Append("</tr>");
            }
            public string Content
            {
                get { return content.ToString(); }
            }
        }
    }
    /// <summary>
    /// Make: make a unique interleaving(varibleID + ins + threadID + index)
    /// Check: check whether the interleaving exist in trace
    /// CalculateSus: calculate sus
    /// </summary>
    public class SuspiciousInterleaving
    {
        //Chen:
        List<Access> _sus = new List<Access>();
        public List<Access> Accesses
        {
            get
            {
                return _sus;
            }
        }

        string _variableID;
        public String VaribleID
        {
            get { return _variableID; }
        }

        /// <summary>
        /// variableID + ins + threadID + index
        /// </summary>
        List<string> _interleaving = new List<string>();

        /// <summary>
        /// variableID + ins + threadID
        /// </summary>
        string _patternID;
        string _index;

        List<ResultAccess> _result = new List<ResultAccess>();

        /// <summary>
        /// variableID + ins + threadID + index
        /// </summary>
        string _uniqueID;
        string _resultID;

        HashSet<string> Pattern = new HashSet<string>() { "RW", "WR", "WW", "WWW", "WWR", "WRW", "RWW", "RWR" };
        string _hitPattern;

        public double aef { get; set; }
        public double aep { get; set; }
        public double anf { get; set; }
        public double anp { get; set; }

        public double score { get; set; }
        public SuspiciousInterleaving(List<Access> accesses)
        {
            foreach (var item in accesses)
            {
                _sus.Add(item);
            }
        }
        public SuspiciousInterleaving() { }
        bool _isRight = false;
        bool _isFeasible = true;
        bool _isChecked = false;
        void Prune()
        {
            //check thread state
            #region
            if (!_sus[0].Restrain.ThreadState.Contains(_sus[1].ThreadID) || !_sus[1].Restrain.ThreadState.Contains(_sus[0].ThreadID))
            {
                _isFeasible = false;
            }
            #endregion
            //check lock
            #region
            if (_sus.Count == 3)
            {
                for (int i = 0; i < _sus[0].Restrain.LockState.Count; i++)
                {
                    for (int j = 0; j < _sus[2].Restrain.LockState.Count; j++)
                    {
                        if (_sus[0].Restrain.LockState[i].name == _sus[2].Restrain.LockState[j].name
                            && _sus[0].Restrain.LockState[i].index == _sus[2].Restrain.LockState[j].index)
                        {
                            for (int k = 0; k < _sus[1].Restrain.LockState.Count; k++)
                            {
                                if (_sus[1].Restrain.LockState[k].name == _sus[0].Restrain.LockState[i].name)
                                {
                                    _isFeasible = false;
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            #endregion
        }
        /// <summary>
        /// Make ID 
        /// </summary>
        public void Make()
        {
            _patternID = "";
            _index = "";
            _uniqueID = "";
            _resultID = "";
            _variableID = "";

            _interleaving.Clear();
            _result.Clear();
            _hitPattern = "";

            aef = 0;
            aep = 0;
            anf = 0;
            anp = 0;

            if (_result.Count == 0)
            {
                _variableID = _sus[0].VariableID;
                for (int i = 0; i < _sus.Count; i++)
                {
                    _patternID += _sus[i].Pattern;
                    _index += _sus[i].Index;
                    _uniqueID += _sus[i].Pattern + _sus[i].Index;

                    _interleaving.Add(_sus[i].Pattern + _sus[i].Index);
                    ResultAccess r = new ResultAccess();


                    r.VariableName = _sus[i].VariableName;
                    r.MethodName = _sus[i].MethodName;
                    r.Instruction = _sus[i].Instruction;
                    _resultID += r.Instruction;
                    r.ThreadID = _sus[i].ThreadID;
                    r.Index = _sus[i].Index;

                    r.url = _sus[i].url;
                    r.startline = _sus[i].startLine;
                    r.endline = _sus[i].endLine;
                    r.starcolumn = _sus[i].startCol;
                    r.endline = _sus[i].endCol;


                    if (_sus[i].Operation == Operation.Read)
                    {
                        r.Operation = "R";
                    }
                    else
                        if (_sus[i].Operation == Operation.Write)
                        {
                            r.Operation = "W";
                        }
                    _result.Add(r);
                }

                foreach (var item in _result)
                {
                    _hitPattern += item.Operation;
                }

                if (!Pattern.Contains(_hitPattern))
                {
                    _isFeasible = false;
                }
            }
        }
        public void Add(Access data)
        {
            _sus.Add(data);
        }
        /// <summary>
        /// check wheterh the interleaving exists in the trace 
        /// </summary>
        /// <param name="trace"></param>
        public void Check(Trajectory trace)
        {
            _isChecked = false;
            if (trace.Interleavings.ContainsKey(this.UniqueID))
            {
                _isChecked = true;

                if (trace.IsRight)
                {
                    this._isRight = true;
                }
                else
                {
                    this._isRight = false;
                }
            }
            Prune();
        }
        public bool isFeasible { get { return _isFeasible; } }
        public bool IsRight { get { return _isRight; } }
        public bool IsChecked { get { return _isChecked; } }
        /// <summary>
        /// This is used for send schedule
        /// </summary>
        public List<string> Interleaving { get { return _interleaving; } }
        public List<ResultAccess> Result { get { return _result; } }
        /// <summary>
        /// variableID + ins + threadID
        /// </summary>
        public string PatternID { get { return _patternID; } }
        /// <summary>
        /// variableID + ins + threadID + index
        /// </summary>
        public string UniqueID { get { return _uniqueID; } }
        /// <summary>
        /// ins
        /// </summary>
        public string ResultID { get { return _resultID; } }
        /// <summary>
        /// indicate Read/Write sequence
        /// </summary>
        public string HitPattern
        {
            get { return _hitPattern; }
        }
        public void CalculateSus(int totalfailed)
        {
            score = (double)aef / (totalfailed + 100 * aep);
        }
        public double GetScore
        {
            get { return score; }
        }
    }
    public class ResultAccess
    {
        public string Instruction;
        public string Operation;
        public int ThreadID;
        public int Index;

        public string url;
        public string MethodName;
        public string VariableName;
        public string SourceCode;

        public int startline;
        public int endline;
        public int starcolumn;
        public int endcolumn;
    }

    /// <summary>
    /// Instructions
    /// </summary>
    public class ResultInterleaving
    {
        public double aef;
        public double aep;
        public double Score;

        string _name;
        public string Name
        {
            get { return _name; }
        }

        List<ResultAccess> _resultAccess;
        public List<ResultAccess> Accesses
        {
            get { return _resultAccess; }
        }

        public ResultInterleaving(SuspiciousInterleaving intl)
        {
            _resultAccess = new List<ResultAccess>();
            foreach (var access in intl.Result)
            {
                _resultAccess.Add(access);
            }
            _name = intl.ResultID;
            aef = 0;
            aep = 0;
            Score = 0;
        }
        public void Calculate(int trialNum, int failNum)
        {
            Score = aef / ((double)failNum + 3.5 * aep);
        }
        public void FindSourceCode()
        {
            Dictionary<string, List<ResultAccess>> dic_url_resAccess = new Dictionary<string,List<ResultAccess>>();
            foreach(var access in _resultAccess)
            {
                if(!dic_url_resAccess.ContainsKey(access.url))
                {
                    dic_url_resAccess[access.url] = new List<ResultAccess>();
                }
                dic_url_resAccess[access.url].Add(access);
            }

            foreach(var url in dic_url_resAccess.Keys)
            {
                string[] lines = File.ReadAllLines(url);
                for(int i =0; i < dic_url_resAccess[url].Count; i++)
                {
                    dic_url_resAccess[url][i].SourceCode = lines[dic_url_resAccess[url][i].startline -1];
                }
            }            
        }
    }

    public class Position
    {
        public int startline;
    }
    public class Trajectory
    {
        List<Access> _trace = new List<Access>();
        bool _isRight = true;
        Dictionary<string, SuspiciousInterleaving> Collection_cover = new Dictionary<string, SuspiciousInterleaving>();
        public Trajectory(List<Access> trace, bool isRight)
        {
            _trace = trace;
            _isRight = isRight;
            RecognizeInterleavings();
        }
        public bool IsRight
        {
            get { return _isRight; }
        }
        public List<Access> Accesses
        {
            get { return _trace; }
        }
        public Trajectory()
        {
        }
        public void Add(Access data)
        {
            _trace.Add(data);
        }
        void RecognizeInterleavings()
        {
            Dictionary<string, List<Access>> VariableTraces = new Dictionary<string, List<Access>>();
            for (int i = 0; i < _trace.Count; i++)
            {
                if (!VariableTraces.ContainsKey(_trace[i].VariableID))
                {
                    VariableTraces[_trace[i].VariableID] = new List<Access>();
                }
                VariableTraces[_trace[i].VariableID].Add(_trace[i]);
            }

            foreach (var variable in VariableTraces.Keys)
            {
                //C_debugFile
                string target_variable = "Account::amount";
                bool isDebug = true;

                if (isDebug && variable.Contains(target_variable))
                {
                    StreamWriter VariableTrace = new StreamWriter(@".\Experiment\" + variable.Replace('.', '_').Replace(':', '_') + ".txt", true);
                    if (_isRight == false)
                    {
                        VariableTrace.WriteLine("Wrong");
                    }
                    foreach (var data in VariableTraces[variable])
                    {
                        VariableTrace.WriteLine(data.Content + "\tline:" + data.startLine);
                    }
                    VariableTrace.Close();
                }
                Dictionary<string, SuspiciousInterleaving> C_debug = new Dictionary<string, SuspiciousInterleaving>();

                HashSet<Tuple<string, string>> MirrorAccess = new HashSet<Tuple<string, string>>();
                HashSet<Tuple<string, string>> DupAccess = new HashSet<Tuple<string, string>>();
                for (int i = 0; i < VariableTraces[variable].Count - 1; i++)
                {
                    int currentThread = VariableTraces[variable][i].ThreadID;
                    List<SuspiciousInterleaving> B_trible = new List<SuspiciousInterleaving>();

                    HashSet<Tuple<string, string>> MirrorAccess_eliminate = new HashSet<Tuple<string, string>>();
                    DupAccess.Clear();
                    bool isTrible = true;
                    for (int j = i + 1; j < VariableTraces[variable].Count; j++)
                    {
                        //pair for trible
                        if (isTrible && VariableTraces[variable][j].ThreadID != currentThread && VariableTraces[variable][i].Restrain.ThreadState.Contains(VariableTraces[variable][j].ThreadID))
                        {
                            Tuple<string, string> pair_tag = new Tuple<string, string>(VariableTraces[variable][i].Pattern, VariableTraces[variable][j].Pattern);
                            Tuple<string, string> pair_tag_reverse = new Tuple<string, string>(VariableTraces[variable][j].Pattern, VariableTraces[variable][i].Pattern);

                            if (MirrorAccess.Contains(pair_tag_reverse))
                            {
                                MirrorAccess_eliminate.Add(pair_tag_reverse);
                                continue;
                            }
                            MirrorAccess.Add(pair_tag);
                            if (DupAccess.Contains(pair_tag))
                            {
                                continue;
                            }
                            DupAccess.Add(pair_tag);

                            SuspiciousInterleaving b_sus = new SuspiciousInterleaving();
                            b_sus.Add(VariableTraces[variable][i]);
                            b_sus.Add(VariableTraces[variable][j]);
                            b_sus.Make();

                            if (b_sus.isFeasible && !Collection_cover.ContainsKey(b_sus.UniqueID))
                            {
                                Collection_cover.Add(b_sus.UniqueID, b_sus);
                                if (isDebug && b_sus.VaribleID.Contains(target_variable))
                                {
                                    C_debug.Add(b_sus.UniqueID, b_sus);
                                }
                            }
                            B_trible.Add(b_sus);
                        }
                        //pair for double
                        else if (VariableTraces[variable][j].ThreadID != currentThread && VariableTraces[variable][i].Restrain.ThreadState.Contains(VariableTraces[variable][j].ThreadID))
                        {
                            SuspiciousInterleaving b_sus = new SuspiciousInterleaving();
                            b_sus.Add(VariableTraces[variable][i]);
                            b_sus.Add(VariableTraces[variable][j]);
                            b_sus.Make();

                            Tuple<string, string> pair_tag = new Tuple<string, string>(VariableTraces[variable][i].Pattern, VariableTraces[variable][j].Pattern);
                            Tuple<string, string> pair_tag_reverse = new Tuple<string, string>(VariableTraces[variable][j].Pattern, VariableTraces[variable][i].Pattern);
                            if (MirrorAccess.Contains(pair_tag_reverse))
                            {
                                MirrorAccess_eliminate.Add(pair_tag_reverse);
                                continue;
                            }
                            MirrorAccess.Add(pair_tag);
                            if (DupAccess.Contains(pair_tag))
                            {
                                continue;
                            }
                            DupAccess.Add(pair_tag);

                            if (b_sus.isFeasible && !Collection_cover.ContainsKey(b_sus.UniqueID))
                            {
                                Collection_cover.Add(b_sus.UniqueID, b_sus);
                                if (isDebug && b_sus.VaribleID.Contains(target_variable))
                                {
                                    C_debug.Add(b_sus.UniqueID, b_sus);
                                }
                            }
                        }
                        //trible
                        else
                        {
                            for (int k = 0; k < B_trible.Count; k++)
                            {
                                SuspiciousInterleaving t_sus = new SuspiciousInterleaving(B_trible[k].Accesses);
                                t_sus.Add(VariableTraces[variable][j]);
                                t_sus.Make();

                                if (t_sus.isFeasible && !Collection_cover.ContainsKey(t_sus.UniqueID))
                                {
                                    Collection_cover.Add(t_sus.UniqueID, t_sus);

                                    if (isDebug && t_sus.VaribleID.Contains(target_variable))
                                    {
                                        C_debug.Add(t_sus.UniqueID, t_sus);
                                    }
                                }
                            }
                            if (VariableTraces[variable][j].Operation == Operation.Write)
                            {
                                isTrible = false;
                                B_trible.Clear();
                            }
                        }
                    }
                    foreach (var t in MirrorAccess_eliminate)
                    {
                        MirrorAccess.Remove(t);
                    }
                }
                //C_debug
                if (isDebug && variable.Contains(target_variable))
                {
                    // string name = variable.Replace('.', '_').Replace(':', '_');
                    StreamWriter VariableTrace = new StreamWriter(@".\Experiment\" + variable.Replace('.', '_').Replace(':', '_') + ".txt", true);
                    foreach (var key in C_debug.Keys)
                    {
                        foreach (var access in C_debug[key].Accesses)
                        {
                            VariableTrace.WriteLine("\t" + access.Content);
                        }
                        VariableTrace.WriteLine();
                    }
                    VariableTrace.Close();
                }
            }
        }
        /// <summary>
        /// key:variableID + ins + threadID + index 
        /// val:SuspiciousInterleaving
        /// </summary>
        public Dictionary<string, SuspiciousInterleaving> Interleavings
        {
            get { return Collection_cover; }
        }
    }
    public class TestGroup
    {
        public string Name;
        List<Access> _Threadx = new List<Access>();
        List<Access> _Thready = new List<Access>();
        public TestGroup(string name)
        {
            Name = name;
        }
        public void Add(Access threadx, Access thready)
        {
            _Threadx.Add(threadx);
            _Thready.Add(thready);
        }
        public void Addx(Access threadx)
        {
            _Threadx.Add(threadx);
        }
        public void Addy(Access thready)
        {
            _Thready.Add(thready);
        }
        public void AddListX(List<Access> threadx)
        {
            for (int i = 0; i < threadx.Count; i++)
            {
                _Threadx.Add(threadx[i]);
            }
        }
        public void AddListY(List<Access> thready)
        {
            for (int i = 0; i < thready.Count; i++)
            {
                _Thready.Add(thready[i]);
            }
        }
        public List<Access> Threadx
        {
            get { return _Threadx; }
        }
        public List<Access> Thready
        {
            get { return _Thready; }
        }
    }
    public class Access
    {
        //chen
        public string _variableID;
        public int _threadID;

        string _patternID;
        int _index;
        string _uniqueID;

        Operation _oper;
        public string _ins;
        Restrain _restrain;

        public string url;
        public int startLine;
        public int endLine;
        public int startCol;
        public int endCol;

        string _variableName;
        public string VariableName
        {
            get { return _variableName; }
        }
        string _methodName;
        public string MethodName
        {
            get { return _methodName; }
        }
        public Access(string variableID, string operation, int threadID, Restrain restrain,string variable_name, string method_name,
            string ins, int index, string url, int startLine, int endLine, int startCol, int endCol)
        {
            this._index = index;
            this._variableID = variableID;
            if (operation == "stfld" || operation == "stsfld")
            {
                this._oper = Operation.Write;
            }
            if (operation == "ldfld" || operation == "ldsfld")
            {
                this._oper = Operation.Read;
            }
            this._threadID = threadID;
            this._ins = ins;
            this._variableName = variable_name;
            this._methodName = method_name;

            this.url = url;
            this.startLine = startLine;
            this.endLine = endLine;
            this.startCol = startCol;
            this.endCol = endCol;
            _restrain = restrain;
            MakeID();
        }
        public Access(string variableID, string operation, int threadID, Restrain restrain, string ins, int index)
        {
            this._index = index;
            this._variableID = variableID;
            if (operation == "stfld" || operation == "stsfld")
            {
                this._oper = Operation.Write;
            }
            if (operation == "ldfld" || operation == "ldsfld")
            {
                this._oper = Operation.Read;
            }
            this._threadID = threadID;
            this._ins = ins;
            _restrain = restrain;
            MakeID();
        }
        void MakeID()
        {
            _patternID = _variableID + _ins + _threadID;
            _uniqueID = _patternID + _index;
        }
        public Operation Operation
        {
            get { return _oper; }
        }

        public Restrain Restrain
        {
            get { return _restrain; }
        }
        public string VariableID
        {
            get { return _variableID; }
        }
        public int ThreadID
        {
            get { return _threadID; }
        }
        public int Index
        {
            get { return _index; }
        }
        public string Instruction
        {
            get { return _ins; }
        }
        /// <summary>
        /// VariableID + ins + threadID
        /// </summary>
        public string Pattern
        {
            get { return _patternID; }
        }
        /// <summary>
        /// PatternID + index
        /// </summary>
        public string Content
        {
            get { return _uniqueID; }
        }
    }
    public class Restrain
    {
        public List<int> ThreadState = new List<int>();
        public List<Lock> LockState = new List<Lock>();
        public List<EventState> EventState = new List<EventState>();
    }
    public class Lock
    {
        public string name;
        public string index;
        public Lock(string name, string index)
        {
            this.name = name;
            this.index = index;
        }
    }
    public class EventState
    {
        public string name;
        public Event e;
    }
    public enum Event
    {
        Set,
        Wait
    }
    /// <summary>
    /// Writer, Read
    /// </summary>
    public enum Operation
    {
        Write,
        Read
    }
}
